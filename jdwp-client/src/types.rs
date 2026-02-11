// JDWP type definitions
//
// Common types used across the JDWP protocol

use serde::{Deserialize, Serialize};

// Object IDs are 8 bytes in JDWP
pub type ObjectId = u64;
pub type ThreadId = ObjectId;
pub type ThreadGroupId = ObjectId;
pub type StringId = ObjectId;
pub type ClassLoaderId = ObjectId;
pub type ClassObjectId = ObjectId;
pub type ArrayId = ObjectId;

pub type ReferenceTypeId = u64;
pub type ClassId = ReferenceTypeId;
pub type InterfaceId = ReferenceTypeId;
pub type ArrayTypeId = ReferenceTypeId;

pub type MethodId = u64;
pub type FieldId = u64;
pub type FrameId = u64;

// Location identifies a code position
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub type_tag: u8, // 1=class, 2=interface, 3=array
    pub class_id: ReferenceTypeId,
    pub method_id: MethodId,
    pub index: u64, // bytecode index (PC)
}

// Thread status values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum ThreadStatus {
    Zombie = 0,
    Running = 1,
    Sleeping = 2,
    Monitor = 3,
    Wait = 4,
}

// Suspend status values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum SuspendStatus {
    Running = 0,
    Suspended = 1,
}

// Type tags for values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TypeTag {
    Array = 91,      // '['
    Byte = 66,       // 'B'
    Char = 67,       // 'C'
    Object = 76,     // 'L'
    Float = 70,      // 'F'
    Double = 68,     // 'D'
    Int = 73,        // 'I'
    Long = 74,       // 'J'
    Short = 83,      // 'S'
    Void = 86,       // 'V'
    Boolean = 90,    // 'Z'
    String = 115,    // 's'
    Thread = 116,    // 't'
    ThreadGroup = 103, // 'g'
    ClassLoader = 108, // 'l'
    ClassObject = 99,  // 'c'
}

// Tagged value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Value {
    pub tag: u8,
    pub data: ValueData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ValueData {
    Byte(i8),
    Char(u16),
    Float(f32),
    Double(f64),
    Int(i32),
    Long(i64),
    Short(i16),
    Boolean(bool),
    Object(ObjectId),
    Void,
}

impl Value {
    /// Format value for display
    pub fn format(&self) -> String {
        match &self.data {
            ValueData::Byte(v) => format!("(byte) {}", v),
            ValueData::Char(v) => format!("(char) '{}'", char::from_u32(*v as u32).unwrap_or('?')),
            ValueData::Float(v) => format!("(float) {}", v),
            ValueData::Double(v) => format!("(double) {}", v),
            ValueData::Int(v) => format!("(int) {}", v),
            ValueData::Long(v) => format!("(long) {}", v),
            ValueData::Short(v) => format!("(short) {}", v),
            ValueData::Boolean(v) => format!("(boolean) {}", v),
            ValueData::Object(id) => {
                if *id == 0 {
                    "(object) null".to_string()
                } else {
                    format!("(object) @{:x}", id)
                }
            }
            ValueData::Void => "(void)".to_string(),
        }
    }
}

// Variable information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variable {
    pub code_index: u64,
    pub name: String,
    pub signature: String,
    pub length: u32,
    pub slot: u32,
}

// Stack frame information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameInfo {
    pub frame_id: FrameId,
    pub location: Location,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_byte() {
        let v = Value { tag: 66, data: ValueData::Byte(42) };
        assert_eq!(v.format(), "(byte) 42");
    }

    #[test]
    fn format_char() {
        let v = Value { tag: 67, data: ValueData::Char(65) };
        assert_eq!(v.format(), "(char) 'A'");
    }

    #[test]
    fn format_float() {
        let v = Value { tag: 70, data: ValueData::Float(1.5) };
        assert_eq!(v.format(), "(float) 1.5");
    }

    #[test]
    fn format_double() {
        let v = Value { tag: 68, data: ValueData::Double(2.5) };
        assert_eq!(v.format(), "(double) 2.5");
    }

    #[test]
    fn format_int() {
        let v = Value { tag: 73, data: ValueData::Int(100) };
        assert_eq!(v.format(), "(int) 100");
    }

    #[test]
    fn format_long() {
        let v = Value { tag: 74, data: ValueData::Long(9999999999) };
        assert_eq!(v.format(), "(long) 9999999999");
    }

    #[test]
    fn format_short() {
        let v = Value { tag: 83, data: ValueData::Short(256) };
        assert_eq!(v.format(), "(short) 256");
    }

    #[test]
    fn format_boolean_true() {
        let v = Value { tag: 90, data: ValueData::Boolean(true) };
        assert_eq!(v.format(), "(boolean) true");
    }

    #[test]
    fn format_boolean_false() {
        let v = Value { tag: 90, data: ValueData::Boolean(false) };
        assert_eq!(v.format(), "(boolean) false");
    }

    #[test]
    fn format_object_null() {
        let v = Value { tag: 76, data: ValueData::Object(0) };
        assert_eq!(v.format(), "(object) null");
    }

    #[test]
    fn format_object_non_null() {
        let v = Value { tag: 76, data: ValueData::Object(0xff) };
        assert_eq!(v.format(), "(object) @ff");
    }

    #[test]
    fn format_void() {
        let v = Value { tag: 86, data: ValueData::Void };
        assert_eq!(v.format(), "(void)");
    }
}
