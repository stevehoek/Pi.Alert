# Pi.Alert Version History
<!--- --------------------------------------------------------------------- --->

  | Version | Description                                                     |
  | ------- | --------------------------------------------------------------- |
  |  v4.00  | Fork with additional features for UniFi users                   |
  |  v3.00  | Major set of New features & Enhancements                        |
  |  v2.70  | New features & Usability improvements in the web prontal        |
  |  v2.61  | Bug fixing                                                      |
  |  v2.60  | Improved the compability of installation process (Ubuntu)       |
  |  v2.56  | Bug fixing                                                      |
  |  v2.55  | Bug fixing                                                      |
  |  v2.52  | Bug fixing                                                      |
  |  v2.51  | Bug fixing                                                      |
  |  v2.50  | First public release                                            |


## Pi.Alert v4.00
<!--- --------------------------------------------------------------------- --->
 **PENDING UPDATE DOC**
  - Added: additional primary scan method for UniFi users (UDM/UDMPro)
  - Added: ability to intelligently set StaticIP and DeviceType on UniFI devices
  - Added: ability to skip Guest and devices with Guest in the client name on UniFi
  - Added: ability to skip clients that don't have a private IP on UniFi
  - Added: option to only report IP changes on StaticIP devices
  - Added: ability to see last scan time and duration in the UI
  - Added: ability to initiate a scan from the UI and see the report when complete
  - Added: improved logging for internet disconnections
  - Added: new Device field for RandomMAC
  - Added: Option to append Group to Name in reports
  - Added: Option to report only StaticIP changes
  - Added: Default value configs for AlertEvents, AlertDown, and ScanCycle
  - Added: ability to copy DHCP leases file from another source (eg: your router) via SCP
  - Added: support for debug config and database, VSCode debugging
  - Changed: ability to disable the arp scan (it is not consistently accurate on most networks)
  - Changed: better validation of IP addresses
  - Changed: database upgrade from within back-end app
  - Changed: updated Python coding style to be more modern
  - Changed: removed branding to be pure GPL
  - Changed: improved code quality


## Pi.Alert v3.02
<!--- --------------------------------------------------------------------- --->
 **PENDING UPDATE DOC**
  - Fixed: UNIQUE constraint failed with Local MAC #114


## Pi.Alert v3.01
<!--- --------------------------------------------------------------------- --->
 **PENDING UPDATE DOC**
  - Fixed: Problem with local MAC & IP (raspberry) #106
 

## Pi.Alert v3.00
<!--- --------------------------------------------------------------------- --->
 **PENDING UPDATE DOC**
  - `arp-scan` config options: interface, several subnets. #101 #15
  - Next/previos button while editing devices #66 #37
  - Internet presence/sessions monitoring #63
  - Logical delete / archive / hide Device #93
  - Flag to mark device with random MAC's #87
  - New Device Types predefined in combobox #92
  - Ask before leave the page with unsaved changes #104
  - Option to don't mark devices as new during installation #94
  - Uninstall script #62
  - Fixed: Error updating name of devices w/o IP #97
  - Fixed: Deleted devices reappear #84
  - Fixed: Device running Pi.Alert must be marked as "on-line" #76
  - Fixed: Incorrect calculation of presence hours #102
  - Fixed: Problem redirect to homepage clicking in logo #103


## Pi.Alert v2.70
<!--- --------------------------------------------------------------------- --->
  - Added Client names resolution #43
  - Added Check to mark devices as "known" #16
  - Remember "Show XXX entries" dropdown value #16 #26
  - Remember "sorting" in devices #16
  - Remember "Device panel " in device detail #16
  - Added "All" option to "Show x Entries" option #16
  - Added optional Location field (Door, Basement, etc.) to devices #16
  - "Device updated successfully" message now is not modal #16
  - Now is possible to delete Devices #16
  - Added Device Type Singleboard Computer (SBC) #16
  - Allowed to use " in device name #42


## Pi.Alert v2.60
<!--- --------------------------------------------------------------------- --->
  - `pialert.conf` moved from `back` to `config` folder
  - `pialert.conf` splitted in two files: `pialert.conf` and `version.conf`
  - Added compatibility with Python 3 (default version installed with Ubuntu)
  - Added compatibility in the Installation guide with Ubuntu server
  - Eliminated some unnecessary packages from the installation


### License
  GPL 3.0
  [Read more here](../LICENSE.txt)

### Contact
  Please create an Issue on GitHub to contact the author.