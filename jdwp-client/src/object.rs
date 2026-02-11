// ObjectReference command implementations
//
// Commands for working with object instances

use crate::commands::{command_sets, object_reference_commands};
use crate::connection::JdwpConnection;
use crate::protocol::{CommandPacket, JdwpResult};
use crate::reader::{read_i32, read_u64, read_u8};
use crate::types::{FieldId, MethodId, ObjectId, ReferenceTypeId, ThreadId, Value, ValueData};
use bytes::{Buf, BufMut};
use serde::{Deserialize, Serialize};

/// Invoke options for method invocation
pub mod invoke_options {
    pub const INVOKE_SINGLE_THREADED: i32 = 0x01;
    pub const INVOKE_NONVIRTUAL: i32 = 0x02;
}

/// Write a tagged value to a buffer (for method invocation arguments)
pub fn write_value_data(buf: &mut impl BufMut, value: &Value) {
    buf.put_u8(value.tag);
    match &value.data {
        ValueData::Byte(v) => buf.put_i8(*v),
        ValueData::Char(v) => buf.put_u16(*v),
        ValueData::Float(v) => buf.put_f32(*v),
        ValueData::Double(v) => buf.put_f64(*v),
        ValueData::Int(v) => buf.put_i32(*v),
        ValueData::Long(v) => buf.put_i64(*v),
        ValueData::Short(v) => buf.put_i16(*v),
        ValueData::Boolean(v) => buf.put_u8(if *v { 1 } else { 0 }),
        ValueData::Object(id) => buf.put_u64(*id),
        ValueData::Void => {},
    }
}

/// Field value from an object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldValue {
    pub field_id: FieldId,
    pub value: Value,
}

impl JdwpConnection {
    /// Get the reference type (class) of an object (ObjectReference.ReferenceType command)
    ///
    /// # Arguments
    /// * `object_id` - The ObjectId of the object
    ///
    /// # Returns
    /// The ReferenceTypeId of the object's class
    pub async fn get_object_reference_type(
        &mut self,
        object_id: ObjectId,
    ) -> JdwpResult<ReferenceTypeId> {
        let id = self.next_id();
        let mut packet = CommandPacket::new(
            id,
            command_sets::OBJECT_REFERENCE,
            object_reference_commands::REFERENCE_TYPE,
        );

        packet.data.put_u64(object_id);

        let reply = self.send_command(packet).await?;
        reply.check_error()?;

        let mut data = reply.data();

        // Read type tag (byte) and class ID (objectID)
        let _type_tag = read_u8(&mut data)?;
        let reference_type_id = read_u64(&mut data)?;

        Ok(reference_type_id)
    }

    /// Invoke a method on an object (ObjectReference.InvokeMethod command)
    ///
    /// Returns (return_value, exception_object_id). If exception_object_id != 0,
    /// the method threw an exception.
    pub async fn invoke_object_method(
        &mut self,
        object_id: ObjectId,
        thread_id: ThreadId,
        class_id: ReferenceTypeId,
        method_id: MethodId,
        args: Vec<Value>,
        options: i32,
    ) -> JdwpResult<(Value, ObjectId)> {
        let id = self.next_id();
        let mut packet = CommandPacket::new(
            id,
            command_sets::OBJECT_REFERENCE,
            object_reference_commands::INVOKE_METHOD,
        );

        packet.data.put_u64(object_id);
        packet.data.put_u64(thread_id);
        packet.data.put_u64(class_id);
        packet.data.put_u64(method_id);

        // Arguments
        packet.data.put_i32(args.len() as i32);
        for arg in &args {
            write_value_data(&mut packet.data, arg);
        }

        // Options
        packet.data.put_i32(options);

        let reply = self.send_command(packet).await?;
        reply.check_error()?;

        let mut data = reply.data();

        // Read return value (tagged)
        let tag = read_u8(&mut data)?;
        let value_data = read_value_by_tag(tag, &mut data)?;
        let return_value = Value { tag, data: value_data };

        // Read exception (tagged object)
        let _exc_tag = read_u8(&mut data)?;
        let exc_id = read_u64(&mut data)?;

        Ok((return_value, exc_id))
    }

    /// Get field values from an object (ObjectReference.GetValues command)
    ///
    /// # Arguments
    /// * `object_id` - The ObjectId of the object
    /// * `field_ids` - Vector of FieldIds to retrieve
    ///
    /// # Returns
    /// Vector of Values corresponding to the requested fields
    ///
    /// # Example
    /// ```no_run
    /// let fields = vec![field_id1, field_id2];
    /// let values = connection.get_object_values(object_id, fields).await?;
    /// ```
    pub async fn get_object_values(
        &mut self,
        object_id: ObjectId,
        field_ids: Vec<FieldId>,
    ) -> JdwpResult<Vec<Value>> {
        let id = self.next_id();
        let mut packet = CommandPacket::new(
            id,
            command_sets::OBJECT_REFERENCE,
            object_reference_commands::GET_VALUES,
        );

        // Write object ID
        packet.data.put_u64(object_id);

        // Write number of fields
        packet.data.put_i32(field_ids.len() as i32);

        // Write each field ID
        for field_id in &field_ids {
            packet.data.put_u64(*field_id);
        }

        let reply = self.send_command(packet).await?;
        reply.check_error()?;

        let mut data = reply.data();

        // Read number of values (should match field_ids.len())
        let values_count = read_i32(&mut data)?;
        let mut values = Vec::with_capacity(values_count as usize);

        for _ in 0..values_count {
            let tag = read_u8(&mut data)?;
            let value_data = read_value_by_tag(tag, &mut data)?;

            values.push(Value {
                tag,
                data: value_data,
            });
        }

        Ok(values)
    }
}

/// Read a value based on its type tag (same as in stackframe.rs)
fn read_value_by_tag(tag: u8, buf: &mut &[u8]) -> JdwpResult<ValueData> {
    match tag {
        // 'B' = byte
        66 => Ok(ValueData::Byte(buf.get_i8())),
        // 'C' = char
        67 => Ok(ValueData::Char(buf.get_u16())),
        // 'D' = double
        68 => Ok(ValueData::Double(buf.get_f64())),
        // 'F' = float
        70 => Ok(ValueData::Float(buf.get_f32())),
        // 'I' = int
        73 => Ok(ValueData::Int(buf.get_i32())),
        // 'J' = long
        74 => Ok(ValueData::Long(buf.get_i64())),
        // 'S' = short
        83 => Ok(ValueData::Short(buf.get_i16())),
        // 'Z' = boolean
        90 => Ok(ValueData::Boolean(buf.get_u8() != 0)),
        // 'V' = void
        86 => Ok(ValueData::Void),
        // Object types (L, s, t, g, l, c, [)
        // L = object, s = string, t = thread, g = thread group, l = class loader, c = class object, [ = array
        76 | 115 | 116 | 103 | 108 | 99 | 91 => {
            let object_id = read_u64(buf)?;
            Ok(ValueData::Object(object_id))
        }
        _ => Err(crate::protocol::JdwpError::Protocol(format!(
            "Unknown value tag: {}",
            tag
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_values_packet() {
        // Test that packet is constructed correctly
    }
}
