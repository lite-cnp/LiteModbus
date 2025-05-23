using LiteModbus.Enums;
using System;
using System.IO;
using System.IO.Ports;
using System.Net.Sockets;
using System.Threading;

namespace LiteModbus;

/// <summary>
/// Implements a ModbusClient.
/// </summary>
public class ModbusClient {

    private const int WRITE_ECHO_LENGTH = 8;
    private const int WRITE_TIMEOUT_MS = 10000;

    private TcpClient tcpClient;
    private SerialPort serialport;

    public byte[] receiveData;
    public byte[] sendData;

    private bool connected = false;

    public delegate void ReceiveDataChangedHandler(object sender);
    public event ReceiveDataChangedHandler ReceiveDataChanged;

    public delegate void SendDataChangedHandler(object sender);
    public event SendDataChangedHandler SendDataChanged;

    public delegate void ConnectedChangedHandler(object sender);
    public event ConnectedChangedHandler ConnectedChanged;

    NetworkStream stream;

    /// <summary>
    /// Gets or Sets the IP-Address of the Server.
    /// </summary>
    public string IpAddress { get; set; } = "127.0.0.1";

    /// <summary>
    /// Gets or Sets the Port were the Modbus-TCP Server is reachable (Standard is 502).
    /// </summary>
    public int Port { get; set; } = 502;

    /// <summary>
    /// Gets or Sets the UDP-Flag to activate Modbus UDP.
    /// </summary>
    public bool UDPFlag { get; set; } = false;

    /// <summary>
    /// Gets or Sets the Unit identifier in case of serial connection (Default = 0)
    /// </summary>
    public byte UnitIdentifier { get; set; } = 0x01;

    /// <summary>
    /// Gets or Sets the Baudrate for serial connection (Default = 9600)
    /// </summary>
    public int Baudrate { get; set; } = 9600;

    /// <summary>
    /// Returns "TRUE" if Client is connected to Server and "FALSE" if not. In case of Modbus RTU returns if COM-Port is opened
    /// </summary>
    public bool Connected {
        get {
            if (serialport != null) {
                return (serialport.IsOpen);
            }

            if (UDPFlag & tcpClient != null) {
                return true;
            }
            if (tcpClient == null) {
                return false;
            }
            else {
                return connected;
            }

        }
    }

    /// <summary>
    /// Gets or Sets the connection Timeout in case of ModbusTCP connection
    /// </summary>
    public int ConnectionTimeout { get; set; } = 1000;


    public ModbusClient(string port, int baudrate, Parity parity, StopBits stopBits) {
        serialport = new() {
            PortName = port,
            BaudRate = baudrate,
            Parity = parity,
            StopBits = stopBits,
            WriteTimeout = 10000,
            ReadTimeout = 10000
        };
    }

    /// <summary>
    /// Creates a serial modbus connection
    /// </summary>
    /// <param name="port"></param>
    /// <param name="baudrate"></param>
    /// <param name="parity"></param>
    /// <param name="stopBits"></param>
    /// <param name="readTimeoutMs"></param>
    /// <param name="connectionTimeoutMs"></param>
    public ModbusClient(string port, int baudrate, Parity parity, StopBits stopBits, int readTimeoutMs, int connectionTimeoutMs) {
        serialport = new() {
            PortName = port,
            BaudRate = baudrate,
            Parity = parity,
            StopBits = stopBits,
            WriteTimeout = readTimeoutMs,
            ReadTimeout = connectionTimeoutMs
        };
    }

    /// <summary>
    /// Constructor which determines the Master ip-address and the Master Port.
    /// </summary>
    /// <param name="ipAddress">IP-Address of the Master device</param>
    /// <param name="port">Listening port of the Master device (should be 502)</param>
    public ModbusClient(string ipAddress, int port) {
        IpAddress = ipAddress;
        Port = port;
    }

    /// <summary>
    /// Constructor which determines the Serial-Port
    /// </summary>
    /// <param name="serialPort">Serial-Port Name e.G. "COM1"</param>
    public ModbusClient(string serialPort) {
        serialport = new() {
            PortName = serialPort
        };
    }

    /// <summary>
    /// Parameterless constructor
    /// </summary>
    public ModbusClient() { }

    /// <summary>
    /// Establish connection to Master device in case of Modbus TCP. Opens COM-Port in case of Modbus RTU
    /// </summary>
    public void Connect() {

        if (serialport.IsOpen) {
            return;
        }

        serialport.Open();
    }

    /// <summary>
    /// Establish connection to Master device in case of Modbus TCP.
    /// </summary>
    public void Connect(string ipAddress, int port) {
        if (!UDPFlag) {
            tcpClient = new TcpClient();
            var result = tcpClient.BeginConnect(ipAddress, port, null, null);
            var success = result.AsyncWaitHandle.WaitOne(ConnectionTimeout);
            if (!success) {
                throw new ConnectionException("connection timed out");
            }
            tcpClient.EndConnect(result);

            //tcpClient = new TcpClient(ipAddress, port);
            stream = tcpClient.GetStream();
            stream.ReadTimeout = ConnectionTimeout;
            connected = true;
        }
        else {
            tcpClient = new TcpClient();
            connected = true;
        }

        ConnectedChanged?.Invoke(this);
    }

    internal static ushort CalculateCRC_2(byte[] data, int offset, int length) {
        ushort crc = 0xFFFF;
        for (int i = offset; i < offset + length; i++) {
            crc ^= data[i];
            for (int bit = 0; bit < 8; bit++) {
                bool lsb = (crc & 0x0001) != 0;
                crc >>= 1;
                if (lsb)
                    crc ^= 0xA001;
            }
        }
        return crc;
    }

    /// <summary>
    /// Calculates the CRC16 for Modbus-RTU
    /// </summary>
    /// <param name="data">Byte buffer to send</param>
    /// <param name="numberOfBytes">Number of bytes to calculate CRC</param>
    /// <param name="startByte">First byte in buffer to start calculating CRC</param>
    internal static ushort CalculateCRC(byte[] data, ushort numberOfBytes, int startByte) {
        byte[] auchCRCHi = [
            0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81,
            0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
            0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01,
            0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
            0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81,
            0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
            0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01,
            0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
            0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81,
            0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
            0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01,
            0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
            0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81,
            0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
            0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01,
            0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
            0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81,
            0x40
        ];

        byte[] auchCRCLo = {
            0x00, 0xC0, 0xC1, 0x01, 0xC3, 0x03, 0x02, 0xC2, 0xC6, 0x06, 0x07, 0xC7, 0x05, 0xC5, 0xC4,
            0x04, 0xCC, 0x0C, 0x0D, 0xCD, 0x0F, 0xCF, 0xCE, 0x0E, 0x0A, 0xCA, 0xCB, 0x0B, 0xC9, 0x09,
            0x08, 0xC8, 0xD8, 0x18, 0x19, 0xD9, 0x1B, 0xDB, 0xDA, 0x1A, 0x1E, 0xDE, 0xDF, 0x1F, 0xDD,
            0x1D, 0x1C, 0xDC, 0x14, 0xD4, 0xD5, 0x15, 0xD7, 0x17, 0x16, 0xD6, 0xD2, 0x12, 0x13, 0xD3,
            0x11, 0xD1, 0xD0, 0x10, 0xF0, 0x30, 0x31, 0xF1, 0x33, 0xF3, 0xF2, 0x32, 0x36, 0xF6, 0xF7,
            0x37, 0xF5, 0x35, 0x34, 0xF4, 0x3C, 0xFC, 0xFD, 0x3D, 0xFF, 0x3F, 0x3E, 0xFE, 0xFA, 0x3A,
            0x3B, 0xFB, 0x39, 0xF9, 0xF8, 0x38, 0x28, 0xE8, 0xE9, 0x29, 0xEB, 0x2B, 0x2A, 0xEA, 0xEE,
            0x2E, 0x2F, 0xEF, 0x2D, 0xED, 0xEC, 0x2C, 0xE4, 0x24, 0x25, 0xE5, 0x27, 0xE7, 0xE6, 0x26,
            0x22, 0xE2, 0xE3, 0x23, 0xE1, 0x21, 0x20, 0xE0, 0xA0, 0x60, 0x61, 0xA1, 0x63, 0xA3, 0xA2,
            0x62, 0x66, 0xA6, 0xA7, 0x67, 0xA5, 0x65, 0x64, 0xA4, 0x6C, 0xAC, 0xAD, 0x6D, 0xAF, 0x6F,
            0x6E, 0xAE, 0xAA, 0x6A, 0x6B, 0xAB, 0x69, 0xA9, 0xA8, 0x68, 0x78, 0xB8, 0xB9, 0x79, 0xBB,
            0x7B, 0x7A, 0xBA, 0xBE, 0x7E, 0x7F, 0xBF, 0x7D, 0xBD, 0xBC, 0x7C, 0xB4, 0x74, 0x75, 0xB5,
            0x77, 0xB7, 0xB6, 0x76, 0x72, 0xB2, 0xB3, 0x73, 0xB1, 0x71, 0x70, 0xB0, 0x50, 0x90, 0x91,
            0x51, 0x93, 0x53, 0x52, 0x92, 0x96, 0x56, 0x57, 0x97, 0x55, 0x95, 0x94, 0x54, 0x9C, 0x5C,
            0x5D, 0x9D, 0x5F, 0x9F, 0x9E, 0x5E, 0x5A, 0x9A, 0x9B, 0x5B, 0x99, 0x59, 0x58, 0x98, 0x88,
            0x48, 0x49, 0x89, 0x4B, 0x8B, 0x8A, 0x4A, 0x4E, 0x8E, 0x8F, 0x4F, 0x8D, 0x4D, 0x4C, 0x8C,
            0x44, 0x84, 0x85, 0x45, 0x87, 0x47, 0x46, 0x86, 0x82, 0x42, 0x43, 0x83, 0x41, 0x81, 0x80,
            0x40
            };

        ushort usDataLen = numberOfBytes;
        byte uchCRCHi = 0xFF;
        byte uchCRCLo = 0xFF;
        int i = 0;
        int uIndex;
        while (usDataLen > 0) {
            usDataLen--;
            if ((i + startByte) < data.Length) {
                uIndex = uchCRCLo ^ data[i + startByte];
                uchCRCLo = (byte)(uchCRCHi ^ auchCRCHi[uIndex]);
                uchCRCHi = auchCRCLo[uIndex];
            }
            i++;
        }
        return (ushort)((ushort)uchCRCHi << 8 | uchCRCLo);
    }

    public static bool DetectValidModbusFrame(byte[] readBuffer, int length) {
        // minimum length 6 bytes
        if (length < 6)
            return false;
        //SlaveID correct
        if ((readBuffer[0] < 1) | (readBuffer[0] > 247))
            return false;
        //CRC correct?
        byte[] crc = new byte[2];
        crc = BitConverter.GetBytes(CalculateCRC(readBuffer, (ushort)(length - 2), 0));
        if (crc[0] != readBuffer[length - 2] | crc[1] != readBuffer[length - 1])
            return false;
        return true;
    }


    /// <summary>
    /// Read Coils from Server device (FC1).
    /// </summary>
    /// <param name="startingAddress">First coil to read</param>
    /// <param name="quantity">Numer of coils to read</param>
    /// <returns>Boolean Array which contains the coils</returns>
    public bool[] ReadCoils(ushort startingAddress, ushort quantity) {
        EnsureSerialPortOpen();

        byte[] pdu = ProtocolDataUnit.ReadCoils(startingAddress, quantity);
        byte[] frame = BuildRtuFrame(pdu);

        serialport.Write(frame, 0, frame.Length);

        int dataBytes = (quantity + 7) / 8;
        int respLen = dataBytes + 5; // 3 for header, 2 for CRC

        byte[] response = new byte[respLen];
        if (serialport.Read(response, 0, respLen) != respLen) {
            throw new TimeoutException($"Expected {respLen} bytes, got less");
        }

        ValidateReadResponse(response, FunctionCodes.READ_COILS, dataBytes);
        return ParseBoolResponse(response, quantity);
    }

    /// <summary>
    /// Read Discrete Inputs from Server device (FC2).
    /// </summary>
    /// <param name="startAddr">First discrete input to read</param>
    /// <param name="qty">Number of discrete Inputs to read</param>
    /// <returns>Boolean Array which contains the discrete Inputs</returns>
    public bool[] ReadDiscreteInputs(ushort startAddr, int qty) {
        EnsureSerialPortOpen();

        byte[] pdu = ProtocolDataUnit.ReadDiscreteInputs(startAddr, (ushort)qty);
        byte[] frame = BuildRtuFrame(pdu);

        serialport.Write(frame, 0, frame.Length);

        int dataBytes = (qty + 7) / 8;
        int respLen = dataBytes + 5;  // 3 for header, 2 for CRC

        byte[] resp = ReadRawResponse(respLen);
        ValidateReadResponse(resp, FunctionCodes.READ_DISCRETE_INPUTS, dataBytes);
        return ParseBoolResponse(resp, qty);
    }

    /// <summary>
    /// Read Holding Registers from Master device (FC3).
    /// </summary>
    /// <param name="startAddr">First holding register to be read</param>
    /// <param name="qty">Number of holding result to be read</param>
    /// <returns>Int Array which contains the holding result</returns>
    public ushort[] ReadHoldingRegisters(ushort startAddr, ushort qty) {
        EnsureSerialPortOpen();

        byte[] pdu = ProtocolDataUnit.ReadHoldingRegisters(startAddr, qty);
        byte[] frame = BuildRtuFrame(pdu);

        serialport.Write(frame, 0, frame.Length);
        Thread.Sleep(15);
        int dataBytes = 2 * qty;
        int respLen = dataBytes + 5;  // 3 for header, 2 for CRC

        byte[] resp = ReadRawResponse(respLen);




        ValidateReadResponse(resp, FunctionCodes.READ_HOLDING_REGISTERS, dataBytes);
        return ParseRegisterResponse(resp, qty);
    }

    /// <summary>
    /// Read Input Registers from Master device (FC4).
    /// </summary>
    /// <param name="startAddr">First input register to be read</param>
    /// <param name="qty">Number of input result to be read</param>
    /// <returns>Int Array which contains the input result</returns>
    public ushort[] ReadInputRegisters(ushort startAddr, ushort qty) {
        EnsureSerialPortOpen();
        byte[] pdu = ProtocolDataUnit.ReadInputRegisters(startAddr, qty);
        byte[] frame = BuildRtuFrame(pdu);

        serialport.Write(frame, 0, frame.Length);

        int dataBytes = qty * 2;
        int respLen = dataBytes + 5;

        byte[] resp = ReadRawResponse(respLen);
        ValidateReadResponse(resp, FunctionCodes.READ_INPUT_REGISTERS, dataBytes);
        return ParseRegisterResponse(resp, qty);
    }

    /// <summary>
    /// Write single Coil to Master device (FC5).
    /// </summary>
    /// <param name="startingAddress">Coil to be written</param>
    /// <param name="value">Coil Value to be written</param>
    public void WriteSingleCoil(ushort address, bool value) {
        EnsureSerialPortOpen();
        byte[] pdu = ProtocolDataUnit.WriteSingleCoil(address, value);
        byte[] frame = BuildRtuFrame(pdu);

        serialport.Write(frame, 0, frame.Length);

        const int RESPONSE_LENGTH = 8;
        byte[] resp = ReadRawResponse(RESPONSE_LENGTH);

        ValidateWriteEcho(resp, FunctionCodes.WRITE_SINGLE_COIL);
    }

    /// <summary>
    /// Write single Register to Master device (FC6).
    /// </summary>
    /// <param name="startingAddress">Register to be written</param>
    /// <param name="value">Register Value to be written</param>
    public void WriteSingleRegister(ushort startAddr, ushort value) {
        EnsureSerialPortOpen();
        byte[] pdu = ProtocolDataUnit.WriteSingleRegister(startAddr, value);
        byte[] frame = BuildRtuFrame(pdu);

        serialport.Write(frame, 0, frame.Length);

        const int RESPONSE_LENGTH = 8;
        byte[] resp = ReadRawResponse(RESPONSE_LENGTH);

        ValidateWriteEcho(resp, FunctionCodes.WRITE_SINGLE_REGISTER);
    }

    /// <summary>
    /// Write multiple coils to Master device (FC15).
    /// </summary>
    /// <param name="startAddr">First coil to be written</param>
    /// <param name="values">Coil Values to be written</param>
    public void WriteMultipleCoils(ushort startAddr, bool[] values) {
        EnsureSerialPortOpen();
        byte[] pdu = ProtocolDataUnit.WriteMultipleCoils(startAddr, values);
        byte[] frame = BuildRtuFrame(pdu);

        serialport.Write(frame, 0, frame.Length);

        byte[] resp = ReadRawResponse(WRITE_ECHO_LENGTH);
        ValidateWriteEcho(resp, FunctionCodes.WRITE_MULTIPLE_COILS);
    }

    /// <summary>
    /// Write multiple result to Master device (FC16).
    /// </summary>
    /// <param name="startAddr">First register to be written</param>
    /// <param name="values">register Values to be written</param>
    public void WriteMultipleRegisters(ushort startAddr, ushort[] values) {
        EnsureSerialPortOpen();
        byte[] pdu = ProtocolDataUnit.WriteMultipleRegisters(startAddr, values);
        byte[] frame = BuildRtuFrame(pdu);

        serialport.Write(frame, 0, frame.Length);

        byte[] resp = ReadRawResponse(WRITE_ECHO_LENGTH);
        ValidateWriteEcho(resp, FunctionCodes.WRITE_MULTIPLE_REGISTERS);
    }

    /// <summary>
    /// Read/Write Multiple Registers (FC23).
    /// </summary>
    /// <param name="startReadAddr">First input register to read</param>
    /// <param name="readQty">Number of input result to read</param>
    /// <param name="startWriteArrd">First input register to write</param>
    /// <param name="values">Values to write</param>
    /// <returns>Int Array which contains the Holding result</returns>
    public ushort[] ReadWriteMultipleRegisters(ushort startReadAddr, ushort readQty, ushort startWriteArrd, ushort[] values) {
        EnsureSerialPortOpen();
        byte[] pdu = ProtocolDataUnit.ReadWriteMultipleRegisters(startReadAddr, readQty, startWriteArrd, values);
        byte[] frame = BuildRtuFrame(pdu);

        serialport.Write(frame, 0, frame.Length);

        int dataBytes = readQty * 2;
        int respLen = dataBytes + 5;

        byte[] response = ReadRawResponse(respLen);

        ValidateReadResponse(response, FunctionCodes.READ_WRITE_MULTIPLE_REGISTERS, dataBytes);

        return ParseRegisterResponse(response, readQty);
    }

    /// <summary>
    /// Close connection to Master Device.
    /// </summary>
    public void Disconnect() {
        serialport?.Close();
        stream?.Close();
        tcpClient?.Close();
        connected = false;
        ConnectedChanged?.Invoke(this);
    }

    /// <summary>
    /// Destructor - Close connection to Master Device.
    /// </summary>
    ~ModbusClient() => Disconnect();

    private void EnsureSerialPortOpen() {
        if (serialport == null || !serialport.IsOpen) {
            throw new SerialPortNotOpenedException("Serial port not opened");
        }
    }

    private byte[] BuildRtuFrame(byte[] pdu) {
        byte[] frame = new byte[pdu.Length + 3];
        frame[0] = UnitIdentifier;
        Buffer.BlockCopy(pdu, 0, frame, 1, pdu.Length);
        ushort crc = CalculateCRC_2(frame, 0, frame.Length - 2);
        frame[frame.Length - 2] = (byte)(crc & 0xFF);
        frame[frame.Length - 1] = (byte)(crc >> 8);
        return frame;
    }

    private byte[] ReadRawResponse(int length) {
        byte[] buffer = new byte[length];
        if (serialport.Read(buffer, 0, length) != length) {
            throw new IOException("Incomplete resp");
        }
        return buffer;
    }

    private void ValidateReadResponse(byte[] resp, FunctionCodes fc, int expectedBytes) {
        if (resp[0] != UnitIdentifier) {
            throw new IOException($"Expected UnitIdentifier {UnitIdentifier} but recieved {resp[0]}");
        }

        if (resp[1] != (byte)fc) {
            throw new IOException($"Expected function code {fc} ({(byte)fc}) but received {(FunctionCodes)resp[1]} ({resp[1]})");
        }

        if (resp[2] != expectedBytes) {
            throw new IOException($"Expected {expectedBytes} data bytes but received {resp[2]}");
        }

        ushort respCrcLo = resp[resp.Length - 2];
        ushort respCrcHi = resp[resp.Length - 1];
        ushort respCrc = (ushort)((respCrcHi << 8) | respCrcLo);
        if (CalculateCRC_2(resp, 0, resp.Length - 2) != respCrc) {
            throw new IOException("CRC validation failed");
        }
    }

    private void ValidateWriteEcho(byte[] resp, FunctionCodes fc) {
        if (resp[0] != UnitIdentifier) {
            throw new IOException($"Expected UnitIdentifier {UnitIdentifier} but recieved {resp[0]}");
        }

        if (resp[1] != (byte)fc) {
            throw new IOException($"Expected function code {fc} ({(byte)fc}) but received {(FunctionCodes)resp[1]} ({resp[1]})");
        }

        ushort respCrcLo = resp[resp.Length - 2];
        ushort respCrcHi = resp[resp.Length - 1];
        ushort respCrc = (ushort)((respCrcHi << 8) | respCrcLo);
        if (CalculateCRC_2(resp, 0, resp.Length - 2) != respCrc) {
            throw new IOException("CRC validation failed");
        }
    }

    private static bool[] ParseBoolResponse(byte[] resp, int count) {
        int byteCount = resp[2];
        byte[] data = new byte[byteCount];
        Buffer.BlockCopy(resp, 3, data, 0, byteCount);
        bool[] result = new bool[count];
        for (int i = 0; i < count; i++) {
            result[i] = (data[i / 8] & (1 << (i % 8))) != 0;
        }
        return result;
    }

    private static ushort[] ParseRegisterResponse(byte[] resp, int qty) {
        int byteCount = resp[2];
        byte[] data = new byte[byteCount];
        Buffer.BlockCopy(resp, 3, data, 0, byteCount);

        ushort[] regs = new ushort[qty];
        for (int i = 0; i < qty; i++) {
            int idx = 2 * i;
            byte hi = data[idx];
            byte lo = data[idx + 1];
            regs[i] = (ushort)(hi << 8 | lo);
        }
        return regs;
    }

    public void WriteFloat(ushort address, float value) {
        byte[] data = BitConverter.GetBytes(value);

        if (!BitConverter.IsLittleEndian) {
            Array.Reverse(data);
        }

        ushort reg1 = (ushort)((data[0] << 8) | data[1]);
        ushort reg2 = (ushort)((data[2] << 8) | data[3]);

        WriteMultipleRegisters(address, [reg1, reg2]);
    }

    public float ReadFloat(ushort address) {
        ushort[] res = ReadHoldingRegisters(address, 2);

        byte[] data = [
            (byte)(res[0] >> 8),
            (byte)res[0],
            (byte)(res[1] >> 8),
            (byte)res[1]
        ];

        if (!BitConverter.IsLittleEndian) {
            Array.Reverse(data);
        }

        return BitConverter.ToSingle(data, 0);
    }

    public ushort ReadRegister(ushort address) {
        ushort[] res = ReadHoldingRegisters(address, 1);
        return res[0];
    }
}
