using LiteModbus.Enums;
using System;

namespace LiteModbus;

internal static class ProtocolDataUnit {

    /// <summary>
    /// Builds a PDU for reading coils (Function Code 1).
    /// </summary>
    internal static byte[] ReadCoils(ushort startingAddress, ushort quantity) {
        if (quantity > 2000) {
            throw new ArgumentOutOfRangeException(nameof(quantity));
        }
        return BuildRequestPdu(FunctionCodes.READ_COILS, startingAddress, quantity);
    }

    /// <summary>
    /// Builds a PDU for reading discrete inputs (Function Code 2).
    /// </summary>
    internal static byte[] ReadDiscreteInputs(ushort startingAddress, ushort quantity) {
        if (quantity > 2000) {
            throw new ArgumentOutOfRangeException(nameof(quantity));
        }
        return BuildRequestPdu(FunctionCodes.READ_DISCRETE_INPUTS, startingAddress, quantity);
    }

    /// <summary>
    /// Builds a PDU for reading holding registers (Function Code 3).
    /// </summary>
    internal static byte[] ReadHoldingRegisters(ushort startingAddress, ushort quantity) {
        if (quantity < 1 || quantity > 123) {
            throw new ArgumentOutOfRangeException(nameof(quantity));
        }
        return BuildRequestPdu(FunctionCodes.READ_HOLDING_REGISTERS, startingAddress, quantity);
    }

    /// <summary>
    /// Builds a PDU for reading input registers (Function Code 4).
    /// </summary>
    internal static byte[] ReadInputRegisters(ushort startingAddress, ushort quantity) {
        if (quantity < 1 || quantity > 125) {
            throw new ArgumentOutOfRangeException(nameof(quantity));
        }
        return BuildRequestPdu(FunctionCodes.READ_INPUT_REGISTERS, startingAddress, quantity);
    }

    /// <summary>
    /// Builds a PDU for writing a single coil (Function Code 5).
    /// </summary>
    internal static byte[] WriteSingleCoil(ushort address, bool value) {
        ushort val = value ? (ushort)0xFF00 : (ushort)0x0000;
        return BuildWritePdu(FunctionCodes.WRITE_SINGLE_COIL, address, val);
    }

    /// <summary>
    /// Builds a PDU for writing a single register (Function Code 6).
    /// </summary>
    internal static byte[] WriteSingleRegister(ushort address, ushort value) {
        return BuildWritePdu(FunctionCodes.WRITE_SINGLE_REGISTER, address, value);
    }

    /// <summary>
    /// Builds a PDU for writing multiple coils (Function Code 15).
    /// </summary>
    internal static byte[] WriteMultipleCoils(ushort startAddress, bool[] values) {
        int quantity = values.Length;
        byte byteCount = (byte)((quantity + 7) / 8);
        byte[] pdu = new byte[6 + byteCount];
        pdu[0] = (byte)FunctionCodes.WRITE_MULTIPLE_COILS;
        pdu[1] = (byte)(startAddress >> 8);
        pdu[2] = (byte)(startAddress & 0xFF);
        pdu[3] = (byte)(quantity >> 8);
        pdu[4] = (byte)(quantity & 0xFF);
        pdu[5] = byteCount;
        for (int i = 0; i < quantity; i++) {
            int byteIndex = i / 8;
            int bitPos = i % 8;
            if (values[i]) pdu[6 + byteIndex] |= (byte)(1 << bitPos);
        }
        return pdu;
    }

    /// <summary>
    /// Builds a PDU for writing multiple registers (Function Code 16).
    /// </summary>
    internal static byte[] WriteMultipleRegisters(ushort startAddress, ushort[] values) {
        int quantity = values.Length;
        if (quantity < 1 || quantity > 123) {
            throw new ArgumentOutOfRangeException(nameof(values));
        }
        byte byteCount = (byte)(quantity * 2);
        byte[] pdu = new byte[6 + byteCount];
        pdu[0] = (byte)FunctionCodes.WRITE_MULTIPLE_REGISTERS;
        pdu[1] = (byte)(startAddress >> 8);
        pdu[2] = (byte)(startAddress & 0xFF);
        pdu[3] = (byte)(quantity >> 8);
        pdu[4] = (byte)(quantity & 0xFF);
        pdu[5] = byteCount;
        for (int i = 0; i < quantity; i++) {
            pdu[6 + 2 * i] = (byte)(values[i] >> 8);
            pdu[7 + 2 * i] = (byte)(values[i] & 0xFF);
        }
        return pdu;
    }

    /// <summary>
    /// Builds a PDU for read/write multiple registers (Function Code 23).
    /// </summary>
    internal static byte[] ReadWriteMultipleRegisters(ushort startReadAddr, ushort readQty, ushort startWriteAddr, ushort[] values) {
        if (readQty < 1 || readQty > 123) {
            throw new ArgumentOutOfRangeException(nameof(readQty));
        }
        int writeQty = values.Length;
        if (writeQty < 1 || writeQty > 123) {
            throw new ArgumentOutOfRangeException(nameof(values));
        }
        int writeByteCount = writeQty * 2;
        byte[] pdu = new byte[10 + writeByteCount];
        pdu[0] = (byte)FunctionCodes.READ_WRITE_MULTIPLE_REGISTERS;
        pdu[1] = (byte)(startReadAddr >> 8);
        pdu[2] = (byte)(startReadAddr & 0xFF);
        pdu[3] = (byte)(readQty >> 8);
        pdu[4] = (byte)(readQty & 0xFF);
        pdu[5] = (byte)(startWriteAddr >> 8);
        pdu[6] = (byte)(startWriteAddr & 0xFF);
        pdu[7] = (byte)(writeQty >> 8);
        pdu[8] = (byte)(writeQty & 0xFF);
        pdu[9] = (byte)writeByteCount;
        for (int i = 0; i < writeQty; i++) {
            pdu[10 + 2 * i] = (byte)(values[i] >> 8);
            pdu[11 + 2 * i] = (byte)(values[i] & 0xFF);
        }
        return pdu;
    }

    private static byte[] BuildRequestPdu(FunctionCodes fc, ushort startingAddress, ushort qty) =>
        new byte[] {
            (byte)fc,
            (byte)(startingAddress >> 8),
            (byte)(startingAddress & 0xFF),
            (byte)(qty >> 8),
            (byte)(qty & 0xFF),
        };

    private static byte[] BuildWritePdu(FunctionCodes fc, ushort address, ushort value) =>
        new byte[] {
            (byte)fc,
            (byte)(address >> 8),
            (byte)(address & 0xFF),
            (byte)(value >> 8),
            (byte)(value & 0xFF),
        };
}