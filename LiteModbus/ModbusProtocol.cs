using System;

namespace LiteModbus;

/// <summary>
/// Modbus Protocol informations.
/// </summary>
public partial class ModbusProtocol {
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
