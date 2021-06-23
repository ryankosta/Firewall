package firewall
import spinal.core._
import spinal.lib._
import spinal.lib.fsm._
import java.nio.file.{Files, Paths}

case class Packet(Size: Int) {
  val content = Vec(Bits(8 bits),Size)
  val currbyte = new Counter(0, Size) 
  def readbyte(index: Int): Bits = content(index)
  def matchpkt(matchwith : Packet): Bool = {
    val retbool = True 
    for( bytenum <- 0 until Size){ 
      retbool := retbool & (content(bytenum) === matchwith.readbyte(bytenum))
    }
    retbool
  }
  def readinFile(path : String): Unit = {
    val data = Files.readAllBytes(Paths.get(path))
    for( bytenum <- 0 until Size){ 
         content(bytenum) := data(bytenum) 
    }
  }
  def readinByte(data : Bits): Unit ={
    content(currbyte) := data
    currbyte.increment()
  }
  def readoutByte(): Bits ={
    val bytereadout = content(currbyte)
    currbyte.increment()
    bytereadout
  }
  def done(): Bool = currbyte.willOverflowIfInc
}


class FirewallTester extends Component{
  val io = new Bundle {
    val rx        = slave Stream(Bits(8 bits))
    val tx        = master  Stream(Bits(8 bits))
  }
  val packetVal = ("path")//TODO: replace with dynamic
  val packetin  =  Packet(1500)
  val packetout =  Packet(1500)

  when(io.rx.ready & !packetout.done()){
    io.rx.valid := True 
    io.rx.payload := packetout.readoutByte() 
  }
  when(io.tx.valid & !packetin.done()){
    io.tx.ready := True
    packetin.readinByte(io.tx.payload)
  }
  assert(packetout.matchpkt(packetin))
}

