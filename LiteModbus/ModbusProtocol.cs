/*
Copyright (c) 2018-2020 Rossmann-Engineering
Permission is hereby granted, free of charge, 
to any person obtaining a copy of this software
and associated documentation files (the "Software"),
to deal in the Software without restriction, 
including without limitation the rights to use, 
copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit 
persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission 
notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, 
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE 
OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

using System;

namespace LiteModbus;

/// <summary>
/// Modbus Protocol informations.
/// </summary>
public class ModbusProtocol {
    public enum ProtocolType { ModbusTCP = 0, ModbusUDP = 1, ModbusRTU = 2 };
    public DateTime timeStamp;
    public bool request;
    public bool response;
    public UInt16 transactionIdentifier;
    public UInt16 protocolIdentifier;
    public UInt16 length;
    public byte unitIdentifier;
    public byte functionCode;
    public UInt16 startingAdress;
    public UInt16 startingAddressRead;
    public UInt16 startingAddressWrite;
    public UInt16 quantity;
    public UInt16 quantityRead;
    public UInt16 quantityWrite;
    public byte byteCount;
    public byte exceptionCode;
    public byte errorCode;
    public UInt16[] receiveCoilValues;
    public UInt16[] receiveRegisterValues;
    public Int16[] sendRegisterValues;
    public bool[] sendCoilValues;
    public UInt16 crc;
}
