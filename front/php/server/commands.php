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
      case 'refreshDevices':    refreshDevices($_REQUEST['cycle']);     break;
      case 'showLatestReport':  showLatestReport($_REQUEST['cycle']);   break;
      default:                  logServerConsole ('Action: '. $action); break;
    }
  }


//------------------------------------------------------------------------------
//  Refresh Devices
//------------------------------------------------------------------------------
function refreshDevices ($cycle) {
  $data = shell_exec("sudo -u pi /usr/bin/python3 ../../../back/pialert.py ".$cycle);
  echo $data;
}

//------------------------------------------------------------------------------
//  Show Latest Report
//------------------------------------------------------------------------------
function showLatestReport ($cycle) {
  $filename = "../../../log/pialert.".$cycle.".log";
  $file = fopen($filename, "r");
  echo fread($file,filesize($filename));
  fclose($file);
}


?>
