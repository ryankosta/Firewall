package firewall
import scala.util.control._
import spinal.core._
import spinal.core.sim._
import spinal.lib._
import spinal.lib.fsm._
import java.nio.file.{Files, Paths}

object Packet {
  def apply(path : String): Packet = new Packet(Files.readAllBytes(Paths.get(path)))
  def apply(size : Int): Packet = new Packet(Array.fill[Byte](size)(0))
}

class FirewallEntries(){
  var entries = List[FirewallEntry]()
  var entrycounter = -1 

  def addEntry(entry : FirewallEntry){
    entries = entry :: entries
    entrycounter += 1
  }

  def done():     Boolean     = entrycounter <= -1
  def readAddr(): Int         = if(entrycounter >= 0) entrycounter else 0
  def readData(): Array[Byte] ={
    val data = entries(entrycounter).getBytes()
    entrycounter -= 1
    data
  }
}

case class FirewallEntry(){
  val entry = Array.fill[Byte](13)(0)

  def getBytes(): Array[Byte] = entry
  def getByte(index : Int): Byte = entry(index) 

  def addProto( b1: Int){
    entry(0) = unsignedCast(b1)
  }

  def unsignedCast(num : Int): Byte ={
    var byte = (0).asInstanceOf[Byte] 
    if(num > 127){
      byte = (num - 256).asInstanceOf[Byte]
    }
    else {
      byte = num.asInstanceOf[Byte]
    }
    byte
  }

  def addSrc(ip : Array[Int], port: Char): Unit = {
    entry(1) = unsignedCast(ip(0)) 
    entry(2) = unsignedCast(ip(1)) 
    entry(3) = unsignedCast(ip(2))
    entry(4) = unsignedCast(ip(3)) 

    entry(9) = (port & -128).asInstanceOf[Byte] //TODO: is this a correct mask 
    entry(10) = (port & (-128 << 8) >> 8).asInstanceOf[Byte] //this might be an arethmetic shift but it shouldnt make a difference
  }

  def addDest(ip : Array[Int], port: Char): Unit = {
    entry(5) = unsignedCast(ip(0)) 
    entry(6) = unsignedCast(ip(1)) 
    entry(7) = unsignedCast(ip(2))
    entry(8) = unsignedCast(ip(3)) 

    entry(11) = (port & -128).asInstanceOf[Byte] //TODO: is this a correct mask 
    entry(12) = (port & (-128 << 8) >> 8).asInstanceOf[Byte] //this might be an arethmetic shift but it shouldnt make a difference

  }
}


class Packet(content: Array[Byte]) {
  var currbyte = 0 //TODO: should be negative 1?
  var nextbyte = 0

  var controllast = false
  var controlin   = false
  var on          = false 
  var txing       = false

  def readin(data: Byte): Boolean = if(nextbyte >= 0) data == content(currbyte) else false 

  def readout():  Byte ={
    var data = (0).asInstanceOf[Byte]
    if(rxvalid()){
      data = content(currbyte) 
    }
    data
  }

  def turnon() : Unit  = on = true 
  def turnoff() : Unit = on = false 

  def donerx()  : Boolean = nextbyte >= content.length
  def donetx()  : Boolean = nextbyte < 0 

  def swapmode() : Unit = txing = !txing 

  def rx(ready : Boolean): Unit = {
    if(!txing){
      controlin = ready
      currbyte  = nextbyte
      if(ready){
        nextbyte = nextbyte + 1
      }
    }
  }
  def rxvalid(): Boolean = !txing && !donerx()  && on 

  def tx(valid : Boolean){
    if(txing){
      controlin = valid
      currbyte = nextbyte
    }
    if(valid && on){
      nextbyte = nextbyte - 1
    }
  }
  def txready(): Boolean = on && txing && nextbyte >= 0
}

object Network {
  object proto {
    val icmp = 1 //NOT officially supported
    val ipv4 = 4
    val tcp  = 6
  }

  object port {
    val ssh   = (22).asInstanceOf[Char]
    val http  = (80).asInstanceOf[Char]
    val ssl   = (443).asInstanceOf[Char]
  }
}

class FirewallTester() extends Component{
  val io = new Bundle {
    val rx        = slave  Stream(Bits(8 bits))
    val tx        = master Stream(Bits(8 bits))
    val data      = in     Bits(104 bits) 
    val writeaddr = in     UInt(U(10).getWidth bits) //TODO make 10 dynamic
    val dvalid    = in     Bool()
  }
  //TODO: remove duplicate code in firewall.scala
  val mac = new Mac()
  val fwmem = new FwMem(10)

  mac.io.tx <> io.tx
  mac.io.rx <> io.rx

  mac.io.fwentry <> fwmem.io.entry
  mac.io.fwdrop  <> fwmem.io.drop
  mac.io.clear   <> fwmem.io.clear

  fwmem.io.writeaddr <> io.writeaddr
  fwmem.io.data      <> io.data
  fwmem.io.writeen   <> io.dvalid

}
object FirewallSim {
  def signedconv(byte : Byte): Int = { 
    var data = byte.asInstanceOf[Int] 
    if(data < 0){
      data += 256
    }
    data
  }
  def main(args: Array[String]){
    SimConfig.withWave.compile{
      val dut = new FirewallTester()
      dut
    }.doSim { dut =>
      dut.clockDomain.forkStimulus(period = 10)

      val packet = Packet("/home/rkosta/dev/packets/packet1")
      val entries = new FirewallEntries()
      val entry   = new FirewallEntry()

      entry.addProto(Network.proto.tcp)
      entry.addDest(Array(10,0,10,57), Network.port.http)
      entry.addSrc( Array(10,0,10,23), Network.port.http)

      entries.addEntry(entry)


      while(!entries.done()){
        dut.clockDomain.waitRisingEdge()

        dut.io.dvalid #= true 
        dut.io.data   #= entries.readData()
        dut.io.writeaddr   #= entries.readAddr()
      }
      dut.io.dvalid #= false 

      packet.turnon()

      val loop = new Breaks;

      loop.breakable {
       while(true){
         dut.clockDomain.waitRisingEdge()

         packet.rx(dut.io.rx.ready.toBoolean)
         dut.io.rx.payload #= signedconv(packet.readout())
         dut.io.rx.valid   #= packet.rxvalid()

         packet.tx(dut.io.tx.valid.toBoolean)
         dut.io.tx.ready   #= packet.txready()

         if(packet.donerx()){
           packet.swapmode()
         }
         if(packet.donetx()){
           packet.turnoff()
           loop.break;
         }
         if(dut.io.tx.valid.toBoolean && packet.txready()){
           assert(packet.readin(dut.io.tx.payload.toInt.asInstanceOf[Byte]))
          }
         }
       }
    }
  }
}
