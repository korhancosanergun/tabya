use crate::model::Expect;

fn same_value(expected: &str, observed: &str) -> bool {
    let (expected, observed) = (expected.trim(), observed.trim());
    match (expected.parse::<i64>(), observed.parse::<i64>()) {
        (Ok(a), Ok(b)) => a == b,
        _ => expected.eq_ignore_ascii_case(observed),
    }
}

impl Expect {
    pub(crate) fn is_empty(&self) -> bool {
        self.equals.is_none()
            && self.one_of.is_none()
            && self.at_least.is_none()
            && self.at_most.is_none()
    }

    /// True when `observed` satisfies every constraint. Text compares
    /// case-insensitively; numeric bounds fail on non-numeric input.
    pub fn matches(&self, observed: &str) -> bool {
        if let Some(expected) = &self.equals {
            if !same_value(&expected.0, observed) {
                return false;
            }
        }
        if let Some(options) = &self.one_of {
            if !options.iter().any(|option| same_value(&option.0, observed)) {
                return false;
            }
        }
        if self.at_least.is_some() || self.at_most.is_some() {
            let Ok(number) = observed.trim().parse::<i64>() else {
                return false;
            };
            if self.at_least.is_some_and(|min| number < min) {
                return false;
            }
            if self.at_most.is_some_and(|max| number > max) {
                return false;
            }
        }
        true
    }

    /// Human readable form used in reports, e.g. `equals "no"`.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(expected) = &self.equals {
            parts.push(format!("equals \"{}\"", expected.0));
        }
        if let Some(options) = &self.one_of {
            let list: Vec<String> = options.iter().map(|o| format!("\"{}\"", o.0)).collect();
            parts.push(format!("one of {}", list.join(", ")));
        }
        if let Some(min) = self.at_least {
            parts.push(format!("at least {min}"));
        }
        if let Some(max) = self.at_most {
            parts.push(format!("at most {max}"));
        }
        parts.join(" and ")
    }
}

#[cfg(test)]
mod tests {
    use crate::model::{Expect, Scalar};

    fn scalar(text: &str) -> Scalar {
        Scalar(text.to_owned())
    }

    #[test]
    fn equals_is_case_insensitive_and_numeric_aware() {
        let expect = Expect {
            equals: Some(scalar("no")),
            ..Expect::default()
        };
        assert!(expect.matches("No"));
        assert!(expect.matches(" no\n"));
        assert!(!expect.matches("yes"));

        let numeric = Expect {
            equals: Some(scalar("1")),
            ..Expect::default()
        };
        assert!(numeric.matches("01"));
        assert!(!numeric.matches("10"));
    }

    #[test]
    fn bounds_and_sets() {
        let range = Expect {
            at_least: Some(1),
            at_most: Some(4),
            ..Expect::default()
        };
        assert!(range.matches("1"));
        assert!(range.matches("4"));
        assert!(!range.matches("0"));
        assert!(!range.matches("5"));
        assert!(!range.matches("many"));
        assert_eq!(range.describe(), "at least 1 and at most 4");

        let set = Expect {
            one_of: Some(vec![scalar("no"), scalar("prohibit-password")]),
            ..Expect::default()
        };
        assert!(set.matches("prohibit-password"));
        assert!(!set.matches("yes"));
    }
}
