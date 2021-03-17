<?php
//------------------------------------------------------------------------------
//  Pi.Alert
//  Open Source Network Guard / WIFI & LAN intrusion detector 
//
//  commands.php - Front module. Server side. Manage Commands
//------------------------------------------------------------------------------
//  GNU GPLv3
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
  // External files
  require 'util.php';
 

//------------------------------------------------------------------------------
//  Action selector
//------------------------------------------------------------------------------
  // Set maximum execution time to 60 seconds
  ini_set ('max_execution_time','60');
  
  // Action functions
  if (isset ($_REQUEST['action']) && !empty ($_REQUEST['action'])) {
    $action = $_REQUEST['action'];
    switch ($action) {
      case 'refreshDevices':  refreshDevices($_REQUEST['cycle']);  break;
      default:     logServerConsole ('Action: '. $action);  break;
    }
  }


//------------------------------------------------------------------------------
//  Refresh Devices
//------------------------------------------------------------------------------
function refreshDevices ($cycle) {
  $data = shell_exec("sudo -u pi python ../../../back/pialert.py ".$cycle);
  echo $data;
}

?>
