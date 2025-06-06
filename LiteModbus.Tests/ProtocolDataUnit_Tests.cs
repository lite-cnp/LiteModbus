using NUnit.Framework;
using LiteModbus;
using LiteModbus.Enums;
using System;
using System.Linq;

namespace LiteModbus.Tests {
	
    [TestFixture]
    public class ProtocolDataUnitTests {
        [TestCase(0x0010, 0x0002, 5, FunctionCodes.READ_COILS, new byte[] { 0x00, 0x10, 0x00, 0x02 })]
        [TestCase(0x0000, 0x0001, 5, FunctionCodes.READ_COILS, new byte[] { 0x00, 0x00, 0x00, 0x01 })]
        public void ReadCoils_Valid_ReturnsExpectedPdu(int start, int qty, int expectedLength, FunctionCodes funcCode, byte[] expectedPayload) {
            byte[] pdu = ProtocolDataUnit.ReadCoils((ushort)start, (ushort)qty);
            Assert.That(pdu.Length, Is.EqualTo(expectedLength));
            Assert.That(pdu[0], Is.EqualTo((byte)funcCode));
            byte[] actualPayload = pdu.Skip(1).ToArray();
            Assert.That(actualPayload, Is.EqualTo(expectedPayload));
        }

        [TestCase(0, 0xFFFF)]
        [TestCase(0, 2001)]
        [TestCase(-1, -10)]
        public void ReadCoils_InvalidQuantity_Throws(int start, int qty) {
            Assert.That(() => ProtocolDataUnit.ReadCoils((ushort)start, (ushort)qty), Throws.TypeOf<ArgumentOutOfRangeException>());
        }

        [Test]
        public void WriteMultipleCoils_BytePacking_CorrectData() {
            int start = 0;
            bool[] values = { true, false, true, false, true, false, true, false };
            byte[] pdu = ProtocolDataUnit.WriteMultipleCoils((ushort)start, values);
            Assert.That(pdu.Length, Is.EqualTo(7));
            Assert.That(pdu[0], Is.EqualTo((byte)FunctionCodes.WRITE_MULTIPLE_COILS));
            Assert.That(pdu[5], Is.EqualTo(1));  // byte count
            Assert.That(pdu[6], Is.EqualTo(0x55));
        }

        [Test]
        public void WriteMultipleRegisters_Valid_CorrectData() {
            int start = 1;
            ushort[] values = { 0x0102, 0x0304 };
            byte[] pdu = ProtocolDataUnit.WriteMultipleRegisters((ushort)start, values);
            Assert.That(pdu.Length, Is.EqualTo(10));
            Assert.That(pdu[0], Is.EqualTo((byte)FunctionCodes.WRITE_MULTIPLE_REGISTERS));
            Assert.That(pdu[1], Is.EqualTo(0x00));
            Assert.That(pdu[2], Is.EqualTo(0x01));
            Assert.That(pdu[3], Is.EqualTo(0x00));
            Assert.That(pdu[4], Is.EqualTo(0x02));
            Assert.That(pdu[5], Is.EqualTo(4));  // byte count
            byte[] actualData = pdu.Skip(6).ToArray();
            Assert.That(actualData, Is.EqualTo(new byte[] { 0x01, 0x02, 0x03, 0x04 }));
        }

        [TestCase(0, new int[0])]
        public void WriteMultipleRegisters_InvalidQuantity_Throws(int start, int[] values) {
            ushort[] casted = Array.ConvertAll(values, v => (ushort)v);
            Assert.That(() => ProtocolDataUnit.WriteMultipleRegisters((ushort)start, casted), Throws.TypeOf<ArgumentOutOfRangeException>());
        }

        [TestCase(1,      1, 2,      new int[] { 0x0003 },                         12, new byte[] { 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x02, 0x00, 0x03 })]
        [TestCase(0,      1, 0,      new int[] { 0x0001 },                         12, new byte[] { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x01 })]
        [TestCase(0,      2, 0,      new int[] { 0x000A, 0x000B },                 14, new byte[] { 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x04, 0x00, 0x0A, 0x00, 0x0B })]
        [TestCase(5,      1, 10,     new int[] { 0x1234 },                         12, new byte[] { 0x00, 0x05, 0x00, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x02, 0x12, 0x34 })]
        [TestCase(255,    3, 100,    new int[] { 0x0001, 0x0002, 0x0003 },         16, new byte[] { 0x00, 0xFF, 0x00, 0x03, 0x00, 0x64, 0x00, 0x03, 0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03 })]
        [TestCase(1,      3, 2,      new int[] { 0xAAAA, 0xBBBB, 0xCCCC, 0xDDDD }, 18, new byte[] { 0x00, 0x01, 0x00, 0x03, 0x00, 0x02, 0x00, 0x04, 0x08, 0xAA, 0xAA, 0xBB, 0xBB, 0xCC, 0xCC, 0xDD, 0xDD })]
        [TestCase(0x1234, 2, 0x5678, new int[] { 0x1111, 0x2222, 0x3333 },         16, new byte[] { 0x12, 0x34, 0x00, 0x02, 0x56, 0x78, 0x00, 0x03, 0x06, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33 })]
        [TestCase(0xFFFF, 1, 0xFFFF, new int[] { 0xFFFF },                         12, new byte[] { 0xFF, 0xFF, 0x00, 0x01, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0xFF, 0xFF })]
        public void ReadWriteMultipleRegisters_Valid_ReturnsExpectedPdu(int startRead, int readQty, int startWrite, int[] writeValues, int expectedLength, byte[] expectedPayload) {
            ushort[] casted = Array.ConvertAll(writeValues, v => (ushort)v);
            byte[] pdu = ProtocolDataUnit.ReadWriteMultipleRegisters((ushort)startRead, (ushort)readQty, (ushort)startWrite, casted);
            Assert.That(pdu.Length, Is.EqualTo(expectedLength));
            Assert.That(pdu[0], Is.EqualTo((byte)FunctionCodes.READ_WRITE_MULTIPLE_REGISTERS));
            byte[] actualPayload = pdu.Skip(1).ToArray();
            Assert.That(actualPayload, Is.EqualTo(expectedPayload));
        }

        [TestCase(0, 0, 0, new int[] { 1 })]
        [TestCase(0, 1, 0, new int[0])]
        public void ReadWriteMultipleRegisters_InvalidQuantity_Throws(int startRead, int readQty, int startWrite, int[] writeValues) {
            ushort[] casted = Array.ConvertAll(writeValues, v => (ushort)v);
            Assert.That(() => ProtocolDataUnit.ReadWriteMultipleRegisters((ushort)startRead, (ushort)readQty, (ushort)startWrite, casted), Throws.TypeOf<ArgumentOutOfRangeException>());
        }
    }

}
