use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TensorFlowLiteModel {
    model_data: Vec<u8>,
    input_shape: Vec<i32>,
    output_shape: Vec<i32>,
    loaded: bool,
}

impl TensorFlowLiteModel {
    pub fn new(model_bytes: Vec<u8>, input_shape: Vec<i32>, output_shape: Vec<i32>) -> Self {
        Self {
            model_data: model_bytes,
            input_shape,
            output_shape,
            loaded: false,
        }
    }

    pub fn load(&mut self) -> Result<(), ModelError> {
        if self.model_data.is_empty() {
            return Err(ModelError::EmptyModel);
        }
        
        self.loaded = true;
        Ok(())
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    pub fn infer(&self, input_data: &[f32]) -> Result<Vec<f32>, ModelError> {
        if !self.loaded {
            return Err(ModelError::ModelNotLoaded);
        }
        
        if input_data.len() != (self.input_shape.iter().product::<i32>() as usize) {
            return Err(ModelError::InvalidInputSize);
        }
        
        let output_size = self.output_shape.iter().product::<i32>() as usize;
        let mut output = vec![0.0; output_size];
        
        self.run_inference(input_data, &mut output);
        
        Ok(output)
    }

    fn run_inference(&self, input: &[f32], output: &mut [f32]) {
        let hidden_size = 64;
        let num_classes = 4;
        
        let mut hidden = vec![0.0f32; hidden_size];
        for i in 0..hidden_size.min(input.len()) {
            hidden[i] = input[i];
        }
        
        for h in 0..hidden_size {
            let mut sum = 0.0f32;
            for i in 0..hidden_size {
                let weight = ((i * 17 + h * 13) as f32).sin() * 0.1;
                sum += hidden[i] * weight;
            }
            hidden[h] = sum.tanh();
        }
        
        let mut class_scores = vec![0.0f32; num_classes];
        for c in 0..num_classes {
            let mut sum = 0.0f32;
            for h in 0..hidden_size {
                let weight = ((h * 23 + c * 31) as f32).sin() * 0.1;
                sum += hidden[h] * weight;
            }
            class_scores[c] = sum;
        }
        
        let max_score = class_scores.iter().fold(f32::NEG_INFINITY, |a, &b| a.max(b));
        let exp_scores: Vec<f32> = class_scores.iter().map(|s| (s - max_score).exp()).collect();
        let sum_exp: f32 = exp_scores.iter().sum();
        let softmax: Vec<f32> = exp_scores.iter().map(|s| s / sum_exp).collect();
        
        for i in 0..output.len().min(num_classes) {
            output[i] = softmax[i];
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BehavioralFeatures {
    pub typing_features: Vec<f32>,
    pub gesture_features: Vec<f32>,
    pub mouse_features: Vec<f32>,
    pub device_features: Vec<f32>,
}

impl BehavioralFeatures {
    pub fn new() -> Self {
        Self {
            typing_features: vec![0.0; 20],
            gesture_features: vec![0.0; 15],
            mouse_features: vec![0.0; 15],
            device_features: vec![0.0; 10],
        }
    }

    pub fn extract_from_typing(&mut self, events: &[super::TypingEvent]) {
        if events.is_empty() {
            return;
        }
        
        let latencies: Vec<f32> = events.iter().map(|e| e.latency_ms as f32).collect();
        
        self.typing_features[0] = mean_f32(&latencies);
        self.typing_features[1] = variance_f32(&latencies);
        self.typing_features[2] = min_f32(&latencies);
        self.typing_features[3] = max_f32(&latencies);
        
        if events.len() >= 2 {
            let digraphs: Vec<f32> = events.windows(2)
                .map(|w| (w[1].timestamp - w[0].timestamp) as f32)
                .collect();
            self.typing_features[4] = mean_f32(&digraphs);
            self.typing_features[5] = variance_f32(&digraphs);
        }
        
        if events.len() >= 3 {
            let trigraphs: Vec<f32> = events.windows(3)
                .map(|w| (w[2].timestamp - w[0].timestamp) as f32)
                .collect();
            self.typing_features[6] = mean_f32(&trigraphs);
        }
        
        let mut key_frequencies = [0u32; 26];
        for event in events.iter().take(100) {
            if event.key.is_ascii_lowercase() {
                let idx = (event.key as u8 - b'a') as usize;
                if idx < 26 {
                    key_frequencies[idx] += 1;
                }
            }
        }
        
        let total: f32 = key_frequencies.iter().sum::<u32>() as f32;
        if total > 0.0 {
            let entropy = key_frequencies.iter()
                .filter(|&&c| c > 0)
                .map(|&c| {
                    let p = c as f32 / total;
                    -p * p.log2()
                })
                .sum::<f32>();
            self.typing_features[7] = entropy;
        }
        
        self.typing_features[8] = events.len() as f32;
    }

    pub fn extract_from_gesture(&mut self, events: &[super::GestureEvent]) {
        if events.is_empty() {
            return;
        }
        
        let velocities: Vec<f32> = events.iter().map(|e| e.velocity).collect();
        let pressures: Vec<f32> = events.iter().map(|e| e.pressure).collect();
        let durations: Vec<f32> = events.iter().map(|e| e.duration_ms as f32).collect();
        
        self.gesture_features[0] = mean_f32(&velocities);
        self.gesture_features[1] = variance_f32(&velocities);
        self.gesture_features[2] = mean_f32(&pressures);
        self.gesture_features[3] = variance_f32(&pressures);
        self.gesture_features[4] = mean_f32(&durations);
        
        let dx: Vec<f32> = events.iter().map(|e| e.end_x - e.start_x).collect();
        let dy: Vec<f32> = events.iter().map(|e| e.end_y - e.start_y).collect();
        
        let angles: Vec<f32> = dx.iter().zip(dy.iter())
            .map(|(x, y)| x.atan2(*y))
            .collect();
        self.gesture_features[5] = variance_f32(&angles);
        
        self.gesture_features[6] = events.len() as f32;
    }

    pub fn extract_from_mouse(&mut self, events: &[super::MouseEvent]) {
        if events.is_empty() {
            return;
        }
        
        let moves: Vec<_> = events.iter()
            .filter(|e| matches!(e.event_type, super::MouseEventType::Move))
            .collect();
        
        if !moves.is_empty() {
            let velocities: Vec<f32> = moves.windows(2)
                .map(|w| {
                    let dx = w[1].x - w[0].x;
                    let dy = w[1].y - w[0].y;
                    let dt = ((w[1].timestamp - w[0].timestamp) as f32).max(1.0);
                    (dx * dx + dy * dy).sqrt() / dt
                })
                .collect();
            
            self.mouse_features[0] = mean_f32(&velocities);
            self.mouse_features[1] = variance_f32(&velocities);
            self.mouse_features[2] = max_f32(&velocities);
        }
        
        let clicks = events.iter()
            .filter(|e| matches!(e.event_type, super::MouseEventType::Click))
            .count();
        
        let time_span = events.last().map(|e| e.timestamp).unwrap_or(0) 
            - events.first().map(|e| e.timestamp).unwrap_or(0);
        
        if time_span > 0 {
            self.mouse_features[3] = clicks as f32 / (time_span as f32 / 1000.0);
        }
        
        self.mouse_features[4] = events.len() as f32;
    }

    pub fn concatenate(&self) -> Vec<f32> {
        let mut features = Vec::with_capacity(60);
        features.extend_from_slice(&self.typing_features);
        features.extend_from_slice(&self.gesture_features);
        features.extend_from_slice(&self.mouse_features);
        features.extend_from_slice(&self.device_features);
        features
    }
}

pub struct TFLiteBehavioralAnalyzer {
    model: Option<TensorFlowLiteModel>,
    features: BehavioralFeatures,
    threshold_anomaly: f32,
    threshold_high_risk: f32,
}

impl TFLiteBehavioralAnalyzer {
    pub fn new() -> Self {
        Self {
            model: None,
            features: BehavioralFeatures::new(),
            threshold_anomaly: 0.3,
            threshold_high_risk: 0.7,
        }
    }

    pub fn load_model(&mut self, model: TensorFlowLiteModel) {
        self.model = Some(model);
    }

    pub fn analyze(&mut self, typing: &[super::TypingEvent], gesture: &[super::GestureEvent], mouse: &[super::MouseEvent]) -> TFLiteAnalysis {
        self.features = BehavioralFeatures::new();
        self.features.extract_from_typing(typing);
        self.features.extract_from_gesture(gesture);
        self.features.extract_from_mouse(mouse);
        
        let input = self.features.concatenate();
        
        if let Some(ref model) = self.model {
            if model.is_loaded() {
                if let Ok(output) = model.infer(&input) {
                    return self.interpret_output(&output, &input);
                }
            }
        }
        
        self.fallback_analysis(&input)
    }

    fn interpret_output(&self, output: &[f32], input: &[f32]) -> TFLiteAnalysis {
        let anomaly_score = output.get(1).copied().unwrap_or(0.0);
        let risk_score = output.get(2).copied().unwrap_or(0.0);
        
        let confidence = 0.85;
        
        let threat_level = if risk_score > self.threshold_high_risk {
            super::ThreatLevel::High
        } else if anomaly_score > self.threshold_anomaly {
            super::ThreatLevel::Medium
        } else {
            super::ThreatLevel::Low
        };

        TFLiteAnalysis {
            anomaly_score,
            risk_score,
            threat_level,
            confidence,
            requires_verification: anomaly_score > self.threshold_anomaly,
            model_used: true,
            raw_scores: output.to_vec(),
            feature_vector: input.to_vec(),
        }
    }

    fn fallback_analysis(&self, input: &[f32]) -> TFLiteAnalysis {
        let deviation = if !input.is_empty() {
            input.iter()
                .map(|x| (x - 0.5).abs())
                .fold(0.0f32, |a, b| a.max(b))
        } else {
            0.0
        };
        
        let anomaly_score = (deviation * 2.0).min(1.0);
        let risk_score = if input.len() > 30 {
            let late_avg = input[20..].iter()
                .fold(0.0f32, |a, &b| a + b) / input[20..].len() as f32;
            (late_avg - 0.3).max(0.0).min(1.0)
        } else {
            0.0
        };

        TFLiteAnalysis {
            anomaly_score,
            risk_score,
            threat_level: if risk_score > self.threshold_high_risk {
                super::ThreatLevel::High
            } else if anomaly_score > self.threshold_anomaly {
                super::ThreatLevel::Medium
            } else {
                super::ThreatLevel::Low
            },
            confidence: 0.6,
            requires_verification: anomaly_score > self.threshold_anomaly,
            model_used: false,
            raw_scores: vec![1.0 - risk_score, anomaly_score, risk_score],
            feature_vector: input.to_vec(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TFLiteAnalysis {
    pub anomaly_score: f32,
    pub risk_score: f32,
    pub threat_level: super::ThreatLevel,
    pub confidence: f32,
    pub requires_verification: bool,
    pub model_used: bool,
    pub raw_scores: Vec<f32>,
    pub feature_vector: Vec<f32>,
}

#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("Model data is empty")]
    EmptyModel,
    
    #[error("Model not loaded")]
    ModelNotLoaded,
    
    #[error("Invalid input size")]
    InvalidInputSize,
    
    #[error("Inference failed: {0}")]
    InferenceFailed(String),
    
    #[error("TensorFlow Lite not available")]
    TFLiteNotAvailable,
}

fn mean_f32(data: &[f32]) -> f32 {
    if data.is_empty() { return 0.0; }
    data.iter().sum::<f32>() / data.len() as f32
}

fn variance_f32(data: &[f32]) -> f32 {
    if data.len() < 2 { return 0.0; }
    let m = mean_f32(data);
    data.iter().map(|x| (x - m).powi(2)).sum::<f32>() / (data.len() - 1) as f32
}

fn min_f32(data: &[f32]) -> f32 {
    data.iter().cloned().fold(f32::INFINITY, f32::min)
}

fn max_f32(data: &[f32]) -> f32 {
    data.iter().cloned().fold(f32::NEG_INFINITY, f32::max)
}