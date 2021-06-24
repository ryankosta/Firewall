Firewall
============

Uses SpinalSBT base project template from https://github.com/SpinalHDL/SpinalTemplateSbt
Open a terminal in the root of it and run "sbt run". At the first execution, the process could take some seconds

```sh
cd Firewall

//If you want to generate the Verilog of your design
sbt "runMain firewall.FirewallVerilog"

//If you want to run the scala written testbench (not yet implemented)
sbt "runMain firewall.FirewallSim"
```

The top level spinal code is defined into src\main\scala\firewall
