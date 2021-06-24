package firewall
import spinal.core._
import spinal.lib._
import spinal.lib.fsm._

class Firewall extends Component{
  val io = new Bundle {
  }
  val mac = new Mac()
  val fwmem = new FwMem(10)
  val dummy = new Dummy()
  mac.io.tx >> dummy.io.tx
  mac.io.rx << dummy.io.rx
//  mac.io.tx <> io.tx
//  mac.io.rx <> io.rx
  mac.io.fwentry <> fwmem.io.entry
  mac.io.fwdrop  <> fwmem.io.drop
  mac.io.clear   <> fwmem.io.clear
}
class Dummy() extends Component{
  val io = new Bundle {
    val rx = master Stream(Bits(8 bits))
    val tx = slave  Stream(Bits(8 bits))
  }
  io.rx.valid   := True
  io.rx.payload := B"00000000"
  io.tx.ready   := True
}
class Mac() extends Component {
  val io = new Bundle {
    val rx      = slave  Stream(Bits(8 bits))
    val tx      = master Stream(Bits(8 bits))
    val fwentry = master Flow(Bits(88 bits)) 
    val fwdrop  = slave  Flow(Bool()) 
    val clear   = out    Bool()
  }
  val bytectr = Counter(0, 1500) //can store upto max packet size
  val fifow   = Fifowatch()
  val rawdata = io.rx.payload
  val pbuff   = PacketBuff()
  pbuff.connectin(io.rx)
  pbuff.connectout(io.tx)
  val pktread = RegInit(False) 
  val clear   = RegInit(True)
  io.clear := clear
  val sz      = Reg(Bits(16 bits))
  val state = new StateMachine{
    val startReading : State = new StateDelay(1) with EntryPoint {
      whenIsActive{
        clear := True
        fifow.clear()
        bytectr.clear()
        pktread     := False
        pbuff.startRx()
        sz          := 0
      }
      whenCompleted{
        goto(readSizeLow)
      }
    }
    val readSizeLow     : State = new StateDelay(1) {
      whenIsActive{
          clear := False
          sz := B"8'x0" ## io.rx.payload
        }
       whenCompleted {
         goto(readSizeHigh)
       }
      }
    val readSizeHigh    : State = new StateDelay(1) {
      whenIsActive{
          sz := sz | (io.rx.payload ## B"8'x0") 
      }
      whenCompleted{
        goto(read)
      }
    }
    val read : State = new State {
      whenIsActive {
        when(bytectr.value <= U(sz)){
          when(io.rx.valid){
            fifow.watch(io.rx.payload,bytectr.value)
            bytectr.increment()
          }
        }.otherwise{
          pktread := True
          pbuff.stopRx()
          when(io.fwdrop.valid){ //wait till fw data present until tx
            goto(tx)
          }
        }
      }
    }
    val tx    : State = new State {
      onEntry{
        when(io.fwdrop.payload){
          pbuff.drop()
          goto(startReading)
        }
        pbuff.startTx()
      }
      whenIsActive{
        when(pbuff.empty()){
          pbuff.stopTx()
          goto(startReading)
        }
      }
    }
    fifow.pmapConnect(bytectr, B"00010000")
  }
}
case class PacketMap(mtu: Int) extends Area{
  val mac_size      = 22
  val iheader_start = mac_size + 2 //accounts for 2 size bytes sent
  val iheader_size  = RegInit(UInt(4 bits))
  val iheader_size_loc = iheader_start 
  val start_proto   = iheader_start + 9 //8 or 9?
  val end_proto     = start_proto 
  val start_ip      = iheader_start + 12 
  val end_ip        = start_ip + 3 
  val start_port    = iheader_start + iheader_size
  val end_port      = start_port + 3 
  val ctr           = UInt(U(mtu).getWidth bits)
  val datastream    = Bits(8 bits) 
  when(ctr === iheader_size_loc){ //TODO: ensure size upcast not downcast
    //TODO: fix, does not account for stream valid being pulled low
    iheader_size := U(datastream(7 downto 4))
  }
  def connectCounter(bytectr : UInt, data : Bits): Unit ={
    ctr := bytectr 
    data := datastream
  }

}
case class Fifowatch() extends Area {
  
  val entry = Vec(Reg(Bits(8 bits)),11) 
  val posctr = Counter(0, 10)
  val pmap   = PacketMap(1500)
  def pmapConnect(bytectr : UInt,data : Bits){ //TODO: Fix nested fxn
    pmap.connectCounter(bytectr,data)
  }

  /*TODO: set maps based on 2+ mac + internet packet not just internet packet*/
  def isip(bytectr    : UInt):  Bool = bytectr >= pmap.start_ip && bytectr <= pmap.end_ip
  def isproto(bytectr : UInt):  Bool =  bytectr === pmap.start_proto 
  def isport(bytectr  : UInt):  Bool = bytectr >= pmap.start_port && bytectr < pmap.end_port
  def isMatch(pktentry : Bits): Bool = pktentry === entry.asBits 
  def clear(): Unit = {
    posctr.clear()
  }
  def isReady(): Bool = posctr.willOverflowIfInc 
  def watch(data : Bits, bytectr : UInt){
    when(isip(bytectr) || isproto(bytectr) || isport(bytectr)){
      entry(posctr) := data
      posctr.increment()
    }
  }
}
/*TODO TODO TODO: define PacketBuff as implicit area
 * make as part of Mac
 */
case class PacketBuff() extends Area{ 
                                        
  val fifo = new StreamFifo(
    Bits(8 bits),
    depth = 1500 
  )
  val rx = RegInit(False)
  val tx = RegInit(False)
  def empty(): Bool = fifo.io.occupancy === 0
  def connectout(stream : Stream[Bits]){
    fifo.io.pop.haltWhen(!tx) <> stream 
  }
  fifo.io.flush := False //TODO: check if this provides a default val
  def drop():    Unit = {
    fifo.io.flush := True
  }
  def startRx(): Unit = {
    rx := True
  }
  def stopRx():  Unit = {
    rx := False
  }
  def startTx(): Unit = {
    tx := True
  }
  def stopTx():  Unit = {
    tx := False
  }
  def connectin(stream : Stream[Bits]){
    //TODO: FIX ADD RX SIGNAL
    val connect = fifo.io.push 
    connect.payload := stream.payload
    connect.valid   := stream.valid
    stream.ready    := connect.ready
  }
}
class FwMem(entries : Int) extends Component {
  val io = new Bundle {
    val writeaddr = in UInt(U(entries).getWidth bits) 
    val data      = in Bits(88 bits)
    val writeen   = in Bool()
    val entry     = slave Flow(Bits(88 bits))
    val drop      = master Flow(Bool())
    val clear     = in Bool()
  }
  val pktentry = Bits(88 bits)
  val mem = Mem(Bits(88 bits), entries) //TODO: make bitsize dynamic based on size of FwEntry() 
  val ctr = Counter(entries)
  mem.write(
    io.writeaddr,
    io.data,
    io.writeen
  )

  val dvalid = RegNext(ctr === entries)
  io.drop.valid := dvalid
  val drop = RegInit(False)
  io.drop.payload := drop
  when(io.clear){
    ctr.clear()
    drop := False
  }.elsewhen(io.entry.valid & !dvalid){
    drop := (pktentry === io.entry.payload) | drop
    ctr.increment()
  }
  pktentry := mem.readSync(
      ctr, 
      io.entry.valid & !dvalid
  )
}

object FirewallVerilog {
  def main(args: Array[String]){
    SpinalVerilog(new Firewall) 
  }
}

case class FwEntry() extends Bundle {
  val ip_src    = Bits(32 bits)
  val ip_dst    = Bits(32 bits)
  val proto     = Bits(8 bits)
  val dest_port = Bits(16 bits)
  def ===(that : FwEntry): Bool = this.asBits === that.asBits

}


