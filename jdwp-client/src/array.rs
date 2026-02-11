// ArrayReference command implementations
//
// Commands for working with array objects

use crate::commands::{command_sets, array_reference_commands};
use crate::connection::JdwpConnection;
use crate::protocol::{CommandPacket, JdwpError, JdwpResult};
use crate::reader::{read_i32, read_u64, read_u8};
use crate::types::{ArrayId, Value, ValueData};
use bytes::{Buf, BufMut};

impl JdwpConnection {
    /// Get the length of an array (ArrayReference.Length command)
    pub async fn get_array_length(&mut self, array_id: ArrayId) -> JdwpResult<i32> {
        let id = self.next_id();
        let mut packet = CommandPacket::new(
            id,
            command_sets::ARRAY_REFERENCE,
            array_reference_commands::LENGTH,
        );

        packet.data.put_u64(array_id);

        let reply = self.send_command(packet).await?;
        reply.check_error()?;

        let mut data = reply.data();
        let length = read_i32(&mut data)?;

        Ok(length)
    }

    /// Get values from an array (ArrayReference.GetValues command)
    pub async fn get_array_values(
        &mut self,
        array_id: ArrayId,
        first_index: i32,
        length: i32,
    ) -> JdwpResult<Vec<Value>> {
        let id = self.next_id();
        let mut packet = CommandPacket::new(
            id,
            command_sets::ARRAY_REFERENCE,
            array_reference_commands::GET_VALUES,
        );

        packet.data.put_u64(array_id);
        packet.data.put_i32(first_index);
        packet.data.put_i32(length);

        let reply = self.send_command(packet).await?;
        reply.check_error()?;

        let mut data = reply.data();

        // Read region tag and count
        let tag = read_u8(&mut data)?;
        let count = read_i32(&mut data)?;

        let mut values = Vec::with_capacity(count as usize);

        // Object types have per-element tags; primitives are untagged
        let is_object_type = matches!(tag, 76 | 115 | 116 | 103 | 108 | 99 | 91);

        for _ in 0..count {
            if is_object_type {
                let elem_tag = read_u8(&mut data)?;
                let object_id = read_u64(&mut data)?;
                values.push(Value {
                    tag: elem_tag,
                    data: ValueData::Object(object_id),
                });
            } else {
                let value_data = read_untagged_value(tag, &mut data)?;
                values.push(Value {
                    tag,
                    data: value_data,
                });
            }
        }

        Ok(values)
    }
}

/// Read an untagged primitive value using the region tag
fn read_untagged_value(tag: u8, buf: &mut &[u8]) -> JdwpResult<ValueData> {
    match tag {
        66 => Ok(ValueData::Byte(buf.get_i8())),        // 'B'
        67 => Ok(ValueData::Char(buf.get_u16())),        // 'C'
        68 => Ok(ValueData::Double(buf.get_f64())),      // 'D'
        70 => Ok(ValueData::Float(buf.get_f32())),       // 'F'
        73 => Ok(ValueData::Int(buf.get_i32())),         // 'I'
        74 => Ok(ValueData::Long(buf.get_i64())),        // 'J'
        83 => Ok(ValueData::Short(buf.get_i16())),       // 'S'
        90 => Ok(ValueData::Boolean(buf.get_u8() != 0)), // 'Z'
        _ => Err(JdwpError::Protocol(format!("Unexpected primitive array tag: {}", tag))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_untagged_byte() {
        let mut buf: &[u8] = &[42];
        let result = read_untagged_value(66, &mut buf).unwrap();
        assert!(matches!(result, ValueData::Byte(42)));
    }

    #[test]
    fn read_untagged_char() {
        let mut buf: &[u8] = &[0x00, 0x41]; // 'A' = 65
        let result = read_untagged_value(67, &mut buf).unwrap();
        assert!(matches!(result, ValueData::Char(65)));
    }

    #[test]
    fn read_untagged_int() {
        let mut buf: &[u8] = &[0x00, 0x00, 0x00, 0x07];
        let result = read_untagged_value(73, &mut buf).unwrap();
        assert!(matches!(result, ValueData::Int(7)));
    }

    #[test]
    fn read_untagged_long() {
        let mut buf: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09];
        let result = read_untagged_value(74, &mut buf).unwrap();
        assert!(matches!(result, ValueData::Long(9)));
    }

    #[test]
    fn read_untagged_float() {
        let bytes = 3.14_f32.to_be_bytes();
        let mut buf: &[u8] = &bytes;
        let result = read_untagged_value(70, &mut buf).unwrap();
        match result {
            ValueData::Float(v) => assert!((v - 3.14).abs() < 0.001),
            _ => panic!("expected Float"),
        }
    }

    #[test]
    fn read_untagged_double() {
        let bytes = 2.718_f64.to_be_bytes();
        let mut buf: &[u8] = &bytes;
        let result = read_untagged_value(68, &mut buf).unwrap();
        match result {
            ValueData::Double(v) => assert!((v - 2.718).abs() < 0.0001),
            _ => panic!("expected Double"),
        }
    }

    #[test]
    fn read_untagged_short() {
        let mut buf: &[u8] = &[0x00, 0x05];
        let result = read_untagged_value(83, &mut buf).unwrap();
        assert!(matches!(result, ValueData::Short(5)));
    }

    #[test]
    fn read_untagged_boolean_true() {
        let mut buf: &[u8] = &[1];
        let result = read_untagged_value(90, &mut buf).unwrap();
        assert!(matches!(result, ValueData::Boolean(true)));
    }

    #[test]
    fn read_untagged_boolean_false() {
        let mut buf: &[u8] = &[0];
        let result = read_untagged_value(90, &mut buf).unwrap();
        assert!(matches!(result, ValueData::Boolean(false)));
    }

    #[test]
    fn read_untagged_unknown_tag_errors() {
        let mut buf: &[u8] = &[0x00];
        let result = read_untagged_value(255, &mut buf);
        assert!(result.is_err());
    }
}
