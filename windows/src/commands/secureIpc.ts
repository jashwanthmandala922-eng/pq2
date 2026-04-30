import { useCallback, useEffect, useRef, useState } from 'react';

interface SecureBuffer {
    data: Uint8Array;
    readonly: boolean;
    timestamp: number;
}

class SecureMemoryManager {
    private static instance: SecureMemoryManager;
    private buffers: Map<string, SecureBuffer> = new Map();
    private readonly MAX_BUFFERS = 5;
    private readonly BUFFER_TIMEOUT_MS = 30000;

    static getInstance(): SecureMemoryManager {
        if (!SecureMemoryManager.instance) {
            SecureMemoryManager.instance = new SecureMemoryManager();
        }
        return SecureMemoryManager.instance;
    }

    createBuffer(id: string, data: Uint8Array, readonly: boolean = false): void {
        if (this.buffers.size >= this.MAX_BUFFERS) {
            this.evictOldest();
        }

        this.buffers.set(id, {
            data: new Uint8Array(data),
            readonly,
            timestamp: Date.now()
        });
    }

    getBuffer(id: string): Uint8Array | null {
        const buffer = this.buffers.get(id);
        if (!buffer) return null;

        if (Date.now() - buffer.timestamp > this.BUFFER_TIMEOUT_MS) {
            this.destroyBuffer(id);
            return null;
        }

        return new Uint8Array(buffer.data);
    }

    destroyBuffer(id: string): void {
        const buffer = this.buffers.get(id);
        if (buffer) {
            buffer.data.fill(0);
            this.buffers.delete(id);
        }
    }

    clearAll(): void {
        for (const [id] of this.buffers) {
            this.destroyBuffer(id);
        }
    }

    private evictOldest(): void {
        let oldestId: string | null = null;
        let oldestTime = Date.now();

        for (const [id, buffer] of this.buffers) {
            if (buffer.timestamp < oldestTime) {
                oldestTime = buffer.timestamp;
                oldestId = id;
            }
        }

        if (oldestId) {
            this.destroyBuffer(oldestId);
        }
    }
}

export function useSecureIPC() {
    const memoryManager = useRef(SecureMemoryManager.getInstance());
    const [isSecure, setIsSecure] = useState(false);

    useEffect(() => {
        setIsSecure(true);

        return () => {
            memoryManager.current.clearAll();
        };
    }, []);

    const invoke = useCallback(async <T>(
        command: string,
        args?: Record<string, unknown>
    ): Promise<T> => {
        try {
            if (args) {
                const serialized = JSON.stringify(args);
                const encoder = new TextEncoder();
                const encoded = encoder.encode(serialized);

                const bufferId = `cmd_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
                memoryManager.current.createBuffer(bufferId, encoded);

                const result = await (window as any).__TAURI__.core.invoke(command, {
                    bufferId,
                    ...args
                });

                memoryManager.current.destroyBuffer(bufferId);
                return result as T;
            }

            return await (window as any).__TAURI__.core.invoke(command);
        } catch (error) {
            console.error(`IPC command ${command} failed:`, error);
            throw error;
        }
    }, []);

    const invokeSecure = useCallback(async <T>(
        command: string,
        sensitiveData?: Record<string, unknown>
    ): Promise<T> => {
        const args = { ...sensitiveData };
        const sensitiveFields = ['password', 'key', 'secret', 'token', 'credential'];

        for (const field of sensitiveFields) {
            if (args[field] && typeof args[field] === 'string') {
                const encoder = new TextEncoder();
                const secretBuffer = encoder.encode(args[field] as string);

                const secureId = `secure_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
                memoryManager.current.createBuffer(secureId, secretBuffer, true);

                args[field] = undefined;
                args[`${field}_buffer_id`] = secureId;
            }
        }

        try {
            const result = await invoke<T>(command, args);

            for (const field of sensitiveFields) {
                const bufferId = args[`${field}_buffer_id` as keyof typeof args] as string;
                if (bufferId) {
                    memoryManager.current.destroyBuffer(bufferId);
                }
            }

            return result;
        } catch (error) {
            for (const field of sensitiveFields) {
                const bufferId = args[`${field}_buffer_id` as keyof typeof args] as string;
                if (bufferId) {
                    memoryManager.current.destroyBuffer(bufferId);
                }
            }
            throw error;
        }
    }, [invoke]);

    const sendEvent = useCallback(async (
        event: string,
        payload?: Record<string, unknown>
    ): Promise<void> => {
        try {
            await (window as any).__TAURI__.event.emit(event, payload);
        } catch (error) {
            console.error(`IPC event ${event} failed:`, error);
            throw error;
        }
    }, []);

    const listenEvent = useCallback((
        event: string,
        callback: (payload: any) => void
    ) => {
        let unsubscribe: (() => void) | null = null;

        (async () => {
            try {
                const { listen } = await import('@tauri-apps/api/event');
                const unlisten = await listen(event, (e) => {
                    if (e.payload) {
                        callback(e.payload);
                    }
                });
                unsubscribe = unlisten;
            } catch (error) {
                console.error(`Failed to listen to event ${event}:`, error);
            }
        })();

        return () => {
            if (unsubscribe) {
                unsubscribe();
            }
        };
    }, []);

    const clearSensitiveMemory = useCallback((): void => {
        memoryManager.current.clearAll();
    }, []);

    return {
        invoke,
        invokeSecure,
        sendEvent,
        listenEvent,
        clearSensitiveMemory,
        isSecure,
    };
}

export function secureWipe(data: Uint8Array): void {
    if (data && data.length > 0) {
        crypto.getRandomValues(data);
        data.fill(0);
    }
}

export function createSecureString(str: string): Uint8Array {
    const encoder = new TextEncoder();
    return encoder.encode(str);
}

export function secureCompare(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;

    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];
    }

    return result === 0;
}

export type { };