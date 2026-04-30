import { useState } from 'react'
import { Lock, Unlock, Key, Settings, Wifi, Plus, Search, Copy, Eye, EyeOff, Shield, Check, X } from 'lucide-react'

type Screen = 'lock' | 'vault' | 'settings' | 'sync'

interface PasswordEntry {
  id: string
  title: string
  username: string
  url: string
}

function App() {
  const [screen, setScreen] = useState<Screen>('lock')
  const [isLocked, setIsLocked] = useState(true)
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')

  const entries: PasswordEntry[] = [
    { id: '1', title: 'Google', username: 'user@gmail.com', url: 'google.com' },
    { id: '2', title: 'GitHub', username: 'dev@github.com', url: 'github.com' },
    { id: '3', title: 'Twitter', username: '@username', url: 'twitter.com' },
    { id: '4', title: 'Netflix', username: 'user@email.com', url: 'netflix.com' },
    { id: '5', title: 'Amazon', username: 'user@amazon.com', url: 'amazon.com' },
  ]

  const filteredEntries = searchQuery 
    ? entries.filter(e => 
        e.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        e.username.toLowerCase().includes(searchQuery.toLowerCase())
      )
    : entries

  const handleUnlock = () => {
    if (password.length >= 4) {
      setIsLocked(false)
      setScreen('vault')
    }
  }

  const handleLock = () => {
    setIsLocked(true)
    setPassword('')
    setScreen('lock')
  }

  if (screen === 'lock' || isLocked) {
    return <LockScreen 
      password={password} 
      setPassword={setPassword} 
      showPassword={showPassword}
      setShowPassword={setShowPassword}
      onUnlock={handleUnlock}
    />
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 via-primary-50/20 to-accent-50/20">
      {/* Header */}
      <header className="glass-card rounded-2xl mx-4 mt-4 p-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-gray-900">SecureVault</h1>
            <p className="text-xs text-gray-500">Post-quantum secure</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button 
            onClick={() => setScreen('sync')}
            className="p-2 rounded-lg hover:bg-gray-100 transition"
          >
            <Wifi className="w-5 h-5 text-gray-600" />
          </button>
          <button 
            onClick={() => setScreen('settings')}
            className="p-2 rounded-lg hover:bg-gray-100 transition"
          >
            <Settings className="w-5 h-5 text-gray-600" />
          </button>
          <button 
            onClick={handleLock}
            className="p-2 rounded-lg hover:bg-gray-100 transition"
          >
            <Lock className="w-5 h-5 text-gray-600" />
          </button>
        </div>
      </header>

      {/* Search */}
      <div className="mx-4 mt-4">
        <div className="glass-input rounded-xl flex items-center px-4 py-3">
          <Search className="w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search passwords..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="flex-1 bg-transparent outline-none ml-3 text-gray-700 placeholder-gray-400"
          />
          {searchQuery && (
            <button onClick={() => setSearchQuery('')}>
              <X className="w-4 h-4 text-gray-400" />
            </button>
          )}
        </div>
      </div>

      {/* Entries */}
      <main className="p-4 pb-24">
        {filteredEntries.length === 0 ? (
          <EmptyState hasSearch={searchQuery.length > 0} />
        ) : (
          <div className="space-y-3">
            {filteredEntries.map((entry) => (
              <EntryCard key={entry.id} entry={entry} />
            ))}
          </div>
        )}
      </main>

      {/* FAB */}
      <button className="fixed bottom-6 right-6 w-14 h-14 rounded-full bg-gradient-to-br from-primary-500 to-accent-500 text-white shadow-lg shadow-primary-500/30 hover:shadow-xl hover:scale-105 transition-all flex items-center justify-center">
        <Plus className="w-6 h-6" />
      </button>

      {/* Bottom Nav */}
      <nav className="fixed bottom-0 left-0 right-0 glass border-t border-white/20">
        <div className="flex justify-around py-3">
          <button className="flex flex-col items-center gap-1 text-primary-600">
            <Key className="w-5 h-5" />
            <span className="text-xs font-medium">Vault</span>
          </button>
          <button 
            onClick={() => setScreen('sync')}
            className="flex flex-col items-center gap-1 text-gray-500 hover:text-primary-600 transition"
          >
            <Wifi className="w-5 h-5" />
            <span className="text-xs">Sync</span>
          </button>
          <button 
            onClick={() => setScreen('settings')}
            className="flex flex-col items-center gap-1 text-gray-500 hover:text-primary-600 transition"
          >
            <Settings className="w-5 h-5" />
            <span className="text-xs">Settings</span>
          </button>
        </div>
      </nav>
    </div>
  )
}

function LockScreen({ password, setPassword, showPassword, setShowPassword, onUnlock }: {
  password: string
  setPassword: (p: string) => void
  showPassword: boolean
  setShowPassword: (s: boolean) => void
  onUnlock: () => void
}) {
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 via-primary-50/30 to-accent-50/30 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="w-20 h-20 rounded-2xl bg-gradient-to-br from-primary-500 to-accent-500 mx-auto mb-4 flex items-center justify-center shadow-lg shadow-primary-500/30">
            <Shield className="w-10 h-10 text-white" />
          </div>
          <h1 className="text-3xl font-bold gradient-text">SecureVault</h1>
          <p className="text-gray-500 mt-1">Post-quantum password manager</p>
        </div>

        {/* Lock Card */}
        <div className="glass-card rounded-2xl p-6 animate-fade-in">
          <h2 className="text-lg font-semibold text-gray-800 mb-1">Welcome Back</h2>
          <p className="text-sm text-gray-500 mb-6">Enter your master password to unlock</p>

          <div className="space-y-4">
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Master password"
                className="w-full glass-input rounded-xl py-3 px-4 pr-12 text-gray-800 placeholder-gray-400 outline-none"
                onKeyDown={(e) => e.key === 'Enter' && onUnlock()}
              />
              <button
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
              >
                {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>

            <button
              onClick={onUnlock}
              disabled={password.length < 4}
              className="w-full glass-button rounded-xl py-3 flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Unlock className="w-5 h-5" />
              <span>Unlock Vault</span>
            </button>
          </div>
        </div>

        {/* Footer */}
        <div className="text-center mt-8">
          <p className="text-xs text-gray-400">ML-KEM • ML-DSA • SPHINCS+</p>
          <p className="text-xs text-gray-400 mt-1">Quantum-resistant encryption</p>
        </div>
      </div>
    </div>
  )
}

function EntryCard({ entry }: { entry: PasswordEntry }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="glass-card rounded-xl p-4 flex items-center gap-4 cursor-pointer">
      <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-primary-100 to-accent-100 flex items-center justify-center">
        <span className="text-lg font-semibold text-primary-600">{entry.title[0]}</span>
      </div>
      <div className="flex-1 min-w-0">
        <h3 className="font-medium text-gray-800 truncate">{entry.title}</h3>
        <p className="text-sm text-gray-500 truncate">{entry.username}</p>
      </div>
      <button 
        onClick={handleCopy}
        className="p-2 rounded-lg hover:bg-gray-100 transition"
      >
        {copied ? (
          <Check className="w-5 h-5 text-green-500" />
        ) : (
          <Copy className="w-5 h-5 text-gray-400" />
        )}
      </button>
    </div>
  )
}

function EmptyState({ hasSearch }: { hasSearch: boolean }) {
  return (
    <div className="flex flex-col items-center justify-center py-16">
      {hasSearch ? (
        <Search className="w-16 h-16 text-gray-300 mb-4" />
      ) : (
        <Key className="w-16 h-16 text-gray-300 mb-4" />
      )}
      <h3 className="text-lg font-medium text-gray-600 mb-1">
        {hasSearch ? 'No results found' : 'No passwords yet'}
      </h3>
      <p className="text-sm text-gray-400">
        {hasSearch ? 'Try a different search' : 'Add your first password'}
      </p>
    </div>
  )
}

export default App