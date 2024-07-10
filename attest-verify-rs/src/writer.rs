#[derive(Debug)]
pub struct Writer {
    inner: Vec<(String, String)>,
}

impl Writer {
    pub fn new() -> Self {
        Self { inner: vec![] }
    }

    pub fn new_with_capacity(capacity: usize) -> Self {
        Self { inner: Vec::with_capacity(capacity) }
    }

    pub fn push<I: Into<String>>(&mut self, attr_name: I, attr_value: I) {
        self.inner.push((attr_name.into(), attr_value.into()));
    }

    pub fn take(self) -> Vec<(String, String)> {
        self.inner
    }

    pub fn to_json_bytes(self) -> Vec<u8> {
        let mut json_str = Vec::new();
        json_str.push(b'{');
        let max_len = self.inner.len();
        for (idx, (key, val)) in self.inner.into_iter().enumerate() {
            let seperator = if idx == max_len -1 {
                ""
            } else {
                ","
            };
            json_str.extend_from_slice(format!(r#""{}":"{}"{}"#, key, val, seperator).as_bytes());
        }
        json_str.push(b'}');
        json_str
    }
}
