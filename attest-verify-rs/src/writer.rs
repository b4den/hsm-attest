use crate::KeyMode;

#[derive(Debug)]
pub struct Writer {
    inner: Vec<(KeyMode, String, String)>,
    mode: KeyMode,
}

impl Writer {
    pub fn new() -> Self {
        Self { inner: vec![], mode: KeyMode::default() }
    }

    pub fn new_with_capacity(capacity: usize) -> Self {
        Self { inner: Vec::with_capacity(capacity), mode: KeyMode::default() }
    }

    pub fn push<I: Into<String>>(&mut self, attr_name: I, attr_value: I, mode: KeyMode) {
        self.inner.push((mode, attr_name.into(), attr_value.into()));
    }

    pub fn take(self) -> Vec<(KeyMode, String, String)> {
        self.inner
    }

    pub fn to_json_bytes(self) -> Vec<u8> {
        let mut json_str = Vec::new();
        json_str.push(b'[');
        json_str.extend_from_slice(format!(r#"{{"mode": "{:?}", "pairs": {{"#, self.mode).as_bytes());
        let max_len = self.inner.len();
        let mut current_mode = self.mode;
        let mut mode_changed = false;
        for (idx, (mode, key, val)) in self.inner.into_iter().enumerate() {
            // close off mode and pairs
            if mode != current_mode {
                json_str.pop();
                json_str.extend_from_slice(format!(r#"}}}}, {{"mode": "{:?}", "pairs": {{"#, mode).as_bytes());
                current_mode = mode;
                mode_changed = true;
            }

            json_str.extend_from_slice(format!(r#""{}":"{}""#, key, val).as_bytes());
            if mode_changed {
                json_str.push(b',');
                mode_changed = false;
            } else if idx != max_len - 1 {
                json_str.push(b',');
            }
        }
        json_str.push(b'}');
        json_str.push(b'}');
        json_str.push(b']');
        json_str
    }
}

/*
 * {
 *   mode: "symmetric",
 *   kv_pairs: { "key": "val"},
 * }
 * }
 * JSON.parse(`[{"mode": "something", "pairs": {"key": "vals"}}, {"mode": "something", "pairs": {"key": "vals"}} ]`);

 */
