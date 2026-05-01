use serde::{Deserialize, Serialize};

const MAX_SAMPLES: usize = 500;
const TYPING_WINDOW_MS: u64 = 100;
const GESTURE_WINDOW_MS: u64 = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypingEvent {
    pub key: char,
    pub latency_ms: u64,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GestureEvent {
    pub start_x: f32,
    pub start_y: f32,
    pub end_x: f32,
    pub end_y: f32,
    pub duration_ms: u64,
    pub pressure: f32,
    pub velocity: f32,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MouseEvent {
    pub x: f32,
    pub y: f32,
    pub delta_x: f32,
    pub delta_y: f32,
    pub timestamp: u64,
    pub event_type: MouseEventType,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum MouseEventType {
    Move,
    Click,
    DoubleClick,
    Drag,
    Scroll,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralProfile {
    pub device_id: String,
    pub typing_samples: Vec<TypingEvent>,
    pub gesture_samples: Vec<GestureEvent>,
    pub mouse_samples: Vec<MouseEvent>,
    pub created_at: u64,
    pub updated_at: u64,
    pub confidence_score: f32,
}

impl BehavioralProfile {
    pub fn new(device_id: String) -> Self {
        Self {
            device_id,
            typing_samples: Vec::new(),
            gesture_samples: Vec::new(),
            mouse_samples: Vec::new(),
            created_at: current_timestamp(),
            updated_at: current_timestamp(),
            confidence_score: 0.0,
        }
    }

    pub fn add_typing_sample(&mut self, event: TypingEvent) {
        if self.typing_samples.len() >= MAX_SAMPLES {
            self.typing_samples.remove(0);
        }
        self.typing_samples.push(event);
        self.updated_at = current_timestamp();
    }

    pub fn add_gesture_sample(&mut self, event: GestureEvent) {
        if self.gesture_samples.len() >= MAX_SAMPLES {
            self.gesture_samples.remove(0);
        }
        self.gesture_samples.push(event);
        self.updated_at = current_timestamp();
    }

    pub fn add_mouse_sample(&mut self, event: MouseEvent) {
        if self.mouse_samples.len() >= MAX_SAMPLES {
            self.mouse_samples.remove(0);
        }
        self.mouse_samples.push(event);
        self.updated_at = current_timestamp();
    }
}

pub struct BehavioralAnalyzer {
    profile: BehavioralProfile,
    baseline_typing: TypingBaseline,
    baseline_gesture: GestureBaseline,
    baseline_mouse: MouseBaseline,
    anomaly_threshold: f32,
    learning_mode: bool,
}

#[derive(Debug, Clone)]
pub struct TypingBaseline {
    pub avg_latency: f64,
    pub std_dev: f64,
    pub key_latencies: std::collections::HashMap<char, (f64, f64)>,
    pub digraph_latencies: std::collections::HashMap<String, f64>,
    pub trigraph_latencies: std::collections::HashMap<String, f64>,
}

#[derive(Debug, Clone)]
pub struct GestureBaseline {
    pub avg_velocity: f32,
    pub avg_pressure: f32,
    pub avg_acceleration: f32,
    pub direction_preferences: std::collections::HashMap<Direction, f32>,
    pub angle_distribution: Vec<f32>,
}

#[derive(Debug, Clone)]
pub struct MouseBaseline {
    pub avg_velocity: f32,
    pub movement_pattern: MovementPattern,
    pub click_frequency: f32,
    pub scroll_pattern: f32,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Up,
    Down,
    Left,
    Right,
    Diagonal,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum MovementPattern {
    Smooth,
    Jerky,
    Rectilinear,
    Circular,
}

impl BehavioralAnalyzer {
    pub fn new(device_id: String) -> Self {
        Self {
            profile: BehavioralProfile::new(device_id),
            baseline_typing: TypingBaseline::new(),
            baseline_gesture: GestureBaseline::new(),
            baseline_mouse: MouseBaseline::new(),
            anomaly_threshold: 0.3,
            learning_mode: true,
        }
    }

    pub fn analyze_typing(&self, samples: &[TypingEvent]) -> TypingAnalysis {
        if samples.len() < 5 {
            return TypingAnalysis {
                is_anomaly: false,
                anomaly_score: 0.0,
                keystroke_dynamics: KeystrokeDynamics::default(),
                typing_pattern: TypingPattern::default(),
                confidence: 0.0,
            };
        }

        let latencies: Vec<u64> = samples.iter().map(|e| e.latency_ms).collect();
        let avg_latency = mean(&latencies);
        let std_dev = std_deviation(&latencies);

        let mut key_speeds = std::collections::HashMap::new();
        for sample in samples {
            let entry = key_speeds.entry(sample.key).or_insert(Vec::new());
            entry.push(sample.latency_ms);
        }

        let mut keystroke_dynamics = KeystrokeDynamics::default();
        keystroke_dynamics.avg_keystroke_latency = avg_latency;
        keystroke_dynamics.keystroke_variance = std_dev;

        let digraphs = calculate_digraphs(samples);
        let digraph_durations: Vec<f64> = digraphs.values().cloned().collect();
        if !digraph_durations.is_empty() {
            keystroke_dynamics.avg_digraph_duration = mean_f64(&digraph_durations);
            keystroke_dynamics.digraph_variance = std_deviation_f64(&digraph_durations);
        }

        let typing_pattern = classify_typing_pattern(samples);

        let baseline = &self.baseline_typing;
        let deviation = ((avg_latency as f32) - (baseline.avg_latency as f32)).abs();

        let is_anomaly = self.learning_mode && deviation > self.anomaly_threshold;
        let anomaly_score = deviation.min(1.0);

        TypingAnalysis {
            is_anomaly,
            anomaly_score,
            keystroke_dynamics,
            typing_pattern,
            confidence: self.profile.confidence_score,
        }
    }

    pub fn analyze_gesture(&self, samples: &[GestureEvent]) -> GestureAnalysis {
        if samples.len() < 3 {
            return GestureAnalysis {
                is_anomaly: false,
                anomaly_score: 0.0,
                gesture_dynamics: GestureDynamics::default(),
                direction_bias: Direction::Up,
                confidence: 0.0,
            };
        }

        let velocities: Vec<f32> = samples.iter().map(|e| e.velocity).collect();
        let avg_velocity = mean_f32(&velocities);

        let pressures: Vec<f32> = samples.iter().map(|e| e.pressure).collect();
        let avg_pressure = mean_f32(&pressures);

        let durations: Vec<u64> = samples.iter().map(|e| e.duration_ms).collect();
        let avg_duration = mean_u64(&durations) as f32;

        let direction = calculate_direction_bias(samples);

        let baseline = &self.baseline_gesture;
        let velocity_deviation = ((avg_velocity - baseline.avg_velocity) / baseline.avg_velocity).abs();
        let pressure_deviation = ((avg_pressure - baseline.avg_pressure) / baseline.avg_pressure).abs();

        let anomaly_score = (velocity_deviation + pressure_deviation) / 2.0;
        let is_anomaly = self.learning_mode && anomaly_score > self.anomaly_threshold;

        GestureAnalysis {
            is_anomaly,
            anomaly_score: anomaly_score.min(1.0),
            gesture_dynamics: GestureDynamics {
                avg_velocity,
                avg_pressure,
                avg_duration,
            },
            direction_bias: direction,
            confidence: self.profile.confidence_score,
        }
    }

    pub fn analyze_mouse(&self, samples: &[MouseEvent]) -> MouseAnalysis {
        if samples.len() < 5 {
            return MouseAnalysis {
                is_anomaly: false,
                anomaly_score: 0.0,
                movement_pattern: MovementPattern::Smooth,
                click_pattern: ClickPattern::default(),
                confidence: 0.0,
            };
        }

        let moves: Vec<&MouseEvent> = samples.iter().filter(|e| e.event_type == MouseEventType::Move).collect();
        
        let velocities: Vec<f32> = moves.iter()
            .map(|e| (e.delta_x.powi(2) + e.delta_y.powi(2)).sqrt())
            .collect();
        let avg_velocity = mean_f32(&velocities);

        let moves_len = moves.len();
        let clicks = samples.iter().filter(|e| matches!(e.event_type, MouseEventType::Click | MouseEventType::DoubleClick)).count();
        let _click_frequency = clicks as f32 / moves_len as f32;

        let pattern = classify_movement_pattern(samples);

        let click_pattern = ClickPattern {
            avg_click_interval: 0.0,
            double_click_rate: 0.0,
        };

        let baseline = &self.baseline_mouse;
        let velocity_deviation = ((avg_velocity - baseline.avg_velocity) / baseline.avg_velocity).abs();

        let is_anomaly = self.learning_mode && velocity_deviation > self.anomaly_threshold;

        MouseAnalysis {
            is_anomaly,
            anomaly_score: velocity_deviation.min(1.0),
            movement_pattern: pattern,
            click_pattern,
            confidence: self.profile.confidence_score,
        }
    }

    pub fn compute_composite_score(
        &self,
        typing: &TypingAnalysis,
        gesture: &GestureAnalysis,
        mouse: &MouseAnalysis,
    ) -> CompositeAnalysis {
        let weights = (0.4, 0.3, 0.3);
        
        let typing_score = if typing.is_anomaly { typing.anomaly_score } else { 0.0 };
        let gesture_score = if gesture.is_anomaly { gesture.anomaly_score } else { 0.0 };
        let mouse_score = if mouse.is_anomaly { mouse.anomaly_score } else { 0.0 };

        let overall_score = 
            weights.0 * typing_score +
            weights.1 * gesture_score +
            weights.2 * mouse_score;

        let confidence = (typing.confidence + gesture.confidence + mouse.confidence) / 3.0;

        let threat_level = if overall_score > 0.7 {
            ThreatLevel::High
        } else if overall_score > 0.4 {
            ThreatLevel::Medium
        } else {
            ThreatLevel::Low
        };

        CompositeAnalysis {
            overall_anomaly_score: overall_score.min(1.0),
            threat_level,
            requires_verification: overall_score > 0.5,
            confidence,
            typing_analysis: typing.clone(),
            gesture_analysis: gesture.clone(),
            mouse_analysis: mouse.clone(),
        }
    }

    pub fn update_baseline(&mut self) {
        if self.profile.typing_samples.len() >= 20 {
            self.baseline_typing = TypingBaseline::from_samples(&self.profile.typing_samples);
        }
        
        if self.profile.gesture_samples.len() >= 10 {
            self.baseline_gesture = GestureBaseline::from_samples(&self.profile.gesture_samples);
        }
        
        if self.profile.mouse_samples.len() >= 20 {
            self.baseline_mouse = MouseBaseline::from_samples(&self.profile.mouse_samples);
        }

        let total_samples = 
            self.profile.typing_samples.len() +
            self.profile.gesture_samples.len() +
            self.profile.mouse_samples.len();
        
        self.profile.confidence_score = (total_samples as f32 / (MAX_SAMPLES as f32 * 3.0)).min(1.0);
    }

    pub fn set_learning_mode(&mut self, enabled: bool) {
        self.learning_mode = enabled;
    }

    pub fn export_profile(&self) -> Vec<u8> {
        serde_json::to_vec(&self.profile).unwrap_or_default()
    }

    pub fn import_profile(&mut self, data: &[u8]) -> Result<(), ()> {
        self.profile = serde_json::from_slice(data).map_err(|_| ())?;
        Ok(())
    }
}

impl TypingBaseline {
    pub fn new() -> Self {
        Self {
            avg_latency: 150.0,
            std_dev: 50.0,
            key_latencies: std::collections::HashMap::new(),
            digraph_latencies: std::collections::HashMap::new(),
            trigraph_latencies: std::collections::HashMap::new(),
        }
    }

    pub fn from_samples(samples: &[TypingEvent]) -> Self {
        let latencies: Vec<u64> = samples.iter().map(|e| e.latency_ms).collect();
        
        let mut key_latencies = std::collections::HashMap::new();
        for sample in samples {
            let entry = key_latencies.entry(sample.key).or_insert(Vec::new());
            entry.push(sample.latency_ms);
        }

        Self {
            avg_latency: mean(&latencies),
            std_dev: std_deviation(&latencies),
            key_latencies: std::collections::HashMap::new(),
            digraph_latencies: std::collections::HashMap::new(),
            trigraph_latencies: std::collections::HashMap::new(),
        }
    }
}

impl GestureBaseline {
    pub fn new() -> Self {
        Self {
            avg_velocity: 500.0,
            avg_pressure: 0.5,
            avg_acceleration: 0.0,
            direction_preferences: std::collections::HashMap::new(),
            angle_distribution: vec![0.25; 4],
        }
    }

    pub fn from_samples(samples: &[GestureEvent]) -> Self {
        let velocities: Vec<f32> = samples.iter().map(|e| e.velocity).collect();
        let pressures: Vec<f32> = samples.iter().map(|e| e.pressure).collect();

        Self {
            avg_velocity: mean_f32(&velocities),
            avg_pressure: mean_f32(&pressures),
            avg_acceleration: 0.0,
            direction_preferences: std::collections::HashMap::new(),
            angle_distribution: vec![0.25; 4],
        }
    }
}

impl MouseBaseline {
    pub fn new() -> Self {
        Self {
            avg_velocity: 300.0,
            movement_pattern: MovementPattern::Smooth,
            click_frequency: 0.1,
            scroll_pattern: 0.0,
        }
    }

    pub fn from_samples(samples: &[MouseEvent]) -> Self {
        let moves: Vec<&MouseEvent> = samples.iter().filter(|e| e.event_type == MouseEventType::Move).collect();
        
        let velocities: Vec<f32> = moves.iter()
            .map(|e| (e.delta_x.powi(2) + e.delta_y.powi(2)).sqrt())
            .collect();

        let clicks = samples.iter().filter(|e| matches!(e.event_type, MouseEventType::Click)).count();
        let click_frequency = if !samples.is_empty() {
            clicks as f32 / samples.len() as f32
        } else {
            0.0
        };

        Self {
            avg_velocity: mean_f32(&velocities),
            movement_pattern: classify_movement_pattern(samples),
            click_frequency,
            scroll_pattern: 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypingAnalysis {
    pub is_anomaly: bool,
    pub anomaly_score: f32,
    pub keystroke_dynamics: KeystrokeDynamics,
    pub typing_pattern: TypingPattern,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeystrokeDynamics {
    pub avg_keystroke_latency: f64,
    pub keystroke_variance: f64,
    pub avg_digraph_duration: f64,
    pub digraph_variance: f64,
    pub error_rate: f32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub enum TypingPattern {
    #[default]
    HuntAndPeck,
    TouchTypist,
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GestureAnalysis {
    pub is_anomaly: bool,
    pub anomaly_score: f32,
    pub gesture_dynamics: GestureDynamics,
    pub direction_bias: Direction,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GestureDynamics {
    pub avg_velocity: f32,
    pub avg_pressure: f32,
    pub avg_duration: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MouseAnalysis {
    pub is_anomaly: bool,
    pub anomaly_score: f32,
    pub movement_pattern: MovementPattern,
    pub click_pattern: ClickPattern,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClickPattern {
    pub avg_click_interval: f32,
    pub double_click_rate: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositeAnalysis {
    pub overall_anomaly_score: f32,
    pub threat_level: ThreatLevel,
    pub requires_verification: bool,
    pub confidence: f32,
    pub typing_analysis: TypingAnalysis,
    pub gesture_analysis: GestureAnalysis,
    pub mouse_analysis: MouseAnalysis,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn mean(data: &[u64]) -> f64 {
    if data.is_empty() { return 0.0; }
    data.iter().sum::<u64>() as f64 / data.len() as f64
}

fn std_deviation(data: &[u64]) -> f64 {
    if data.len() < 2 { return 0.0; }
    let m = mean(data);
    let variance = data.iter()
        .map(|x| (*x as f64 - m).powi(2))
        .sum::<f64>() / (data.len() - 1) as f64;
    variance.sqrt()
}

fn mean_f64(data: &[f64]) -> f64 {
    if data.is_empty() { return 0.0; }
    data.iter().sum::<f64>() / data.len() as f64
}

fn std_deviation_f64(data: &[f64]) -> f64 {
    if data.len() < 2 { return 0.0; }
    let m = mean_f64(data);
    let variance = data.iter()
        .map(|x| (*x - m).powi(2))
        .sum::<f64>() / (data.len() - 1) as f64;
    variance.sqrt()
}

fn mean_f32(data: &[f32]) -> f32 {
    if data.is_empty() { return 0.0; }
    data.iter().sum::<f32>() / data.len() as f32
}

fn mean_u64(data: &[u64]) -> f64 {
    if data.is_empty() { return 0.0; }
    data.iter().sum::<u64>() as f64 / data.len() as f64
}

fn calculate_digraphs(samples: &[TypingEvent]) -> std::collections::HashMap<String, f64> {
    let mut digraph_map = std::collections::HashMap::new();
    let chars: Vec<char> = samples.iter().map(|e| e.key).collect();
    
    for window in chars.windows(2) {
        let digraph_key = format!("{}{}", window[0], window[1]);
        if let Some(idx) = chars.windows(2).position(|w| w[0] == window[0] && w[1] == window[1]) {
            let latency = samples.get(idx).map(|e| e.latency_ms as f64).unwrap_or(0.0);
            *digraph_map.entry(digraph_key).or_insert(0.0) += latency;
        }
    }
    digraph_map
}

fn classify_typing_pattern(samples: &[TypingEvent]) -> TypingPattern {
    if samples.is_empty() {
        return TypingPattern::default();
    }
    
    let latencies: Vec<u64> = samples.iter().map(|e| e.latency_ms).collect();
    let std_dev = std_deviation(&latencies);
    let avg = mean(&latencies);
    
    if std_dev / avg < 0.3 {
        TypingPattern::TouchTypist
    } else if std_dev / avg > 0.7 {
        TypingPattern::HuntAndPeck
    } else {
        TypingPattern::Hybrid
    }
}

fn calculate_direction_bias(samples: &[GestureEvent]) -> Direction {
    let mut direction_counts = std::collections::HashMap::new();
    
    for sample in samples {
        let dx = sample.end_x - sample.start_x;
        let dy = sample.end_y - sample.start_y;
        
        let dir = if dx.abs() > dy.abs() {
            if dx > 0.0 { Direction::Right } else { Direction::Left }
        } else {
            if dy > 0.0 { Direction::Down } else { Direction::Up }
        };
        
        *direction_counts.entry(dir).or_insert(0) += 1;
    }

    direction_counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(dir, _)| dir)
        .unwrap_or(Direction::Up)
}

fn classify_movement_pattern(samples: &[MouseEvent]) -> MovementPattern {
    let moves: Vec<&MouseEvent> = samples.iter()
        .filter(|e| e.event_type == MouseEventType::Move)
        .collect();
    
    if moves.len() < 2 {
        return MovementPattern::Smooth;
    }

    let angles: Vec<f32> = moves.windows(2)
        .map(|w| {
            let dx = w[1].x - w[0].x;
            let dy = w[1].y - w[0].y;
            dx.atan2(dy).abs()
        })
        .collect();
    
    let angle_variance = variance_f32(&angles);
    
    if angle_variance < 0.1 {
        MovementPattern::Rectilinear
    } else if angle_variance < 0.5 {
        MovementPattern::Smooth
    } else {
        MovementPattern::Jerky
    }
}

fn variance_f32(data: &[f32]) -> f32 {
    if data.len() < 2 { return 0.0; }
    let m = mean_f32(data);
    data.iter().map(|x| (x - m).powi(2)).sum::<f32>() / (data.len() - 1) as f32
}