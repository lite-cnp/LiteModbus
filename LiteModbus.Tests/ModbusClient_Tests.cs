namespace LiteModbus.Tests;

[TestFixture]
public class ModbusClientTests {

    [TestCase(new byte[] { },                              0xFFFF)]
    [TestCase(new byte[] { 1, 3, 2, 0, 10 },               0x4338)]
    [TestCase(new byte[] { 1, 2, 3, 4 },                   0x2BA1)]
    [TestCase(new byte[] { 255 },                          0x00FF)]
    [TestCase(new byte[] { 0xAB, 0xCD },                   0x15BF)]
    [TestCase(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, 0x4574)]
    [TestCase(new byte[] { 255, 0, 255, 0 },               0xC071)]
    [TestCase(new byte[] { 1, 2 },                         0xE181)]
    public void CalculateCRC_ReturnsExpected(byte[] data, int expected) {
        ushort result = ModbusClient.CalculateCRC(data, (ushort)data.Length, 0);
        Assert.That(result, Is.EqualTo((ushort)expected));
    }

    [TestCase(new byte[] { },                              0xFFFF)]
    [TestCase(new byte[] { 1, 3, 2, 0, 10 },               0x4338)]
    [TestCase(new byte[] { 1, 2, 3, 4 },                   0x2BA1)]
    [TestCase(new byte[] { 255 },                          0x00FF)]
    [TestCase(new byte[] { 0xAB, 0xCD },                   0x15BF)]
    [TestCase(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, 0x4574)]
    [TestCase(new byte[] { 255, 0, 255, 0 },               0xC071)]
    [TestCase(new byte[] { 1, 2 },                         0xE181)]
    public void CalculateCRC_2_ReturnsExpected(byte[] data, int expected) {
        ushort result = ModbusClient.CalculateCRC_2(data, 0, (ushort)data.Length);
        Assert.That(result, Is.EqualTo((ushort)expected));
    }
}