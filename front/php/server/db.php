<?php
//------------------------------------------------------------------------------
//  Pi.Alert
//  Open Source Network Guard / WIFI & LAN intrusion detector 
//
//  db.php - Front module. Server side. DB common file
//------------------------------------------------------------------------------
//  GNU GPLv3
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
// DB File Path
$DBFILE = '../../../db/pialert.db';


//------------------------------------------------------------------------------
// Connect DB
//------------------------------------------------------------------------------
function SQLite3_connect ($trytoreconnect, $readonly) {
  global $DBFILE;

  try
  {
    // connect to database
    if($readonly) 
    {
      return new SQLite3($DBFILE, SQLITE3_OPEN_READONLY);
    }
    else
    {
      return new SQLite3($DBFILE, SQLITE3_OPEN_READWRITE);
    }
  }
  catch (Exception $exception)
  {
    // sqlite3 throws an exception when it is unable to connect
    // try to reconnect one time after 3 seconds
    if($trytoreconnect)
    {
      sleep(3);
      return SQLite3_connect(false, $readonly);
    }
  }
}


//------------------------------------------------------------------------------
// Open DB
//------------------------------------------------------------------------------
function OpenDB ($readonly) {
  global $DBFILE;
  global $db;

  if(strlen($DBFILE) == 0)
  {
    die ('Database not configured');
  }

  $db = SQLite3_connect(true, $readonly);
  if(!$db)
  {
    die ('Error connecting to database');
  }
}


//------------------------------------------------------------------------------
// Close DB
//------------------------------------------------------------------------------
function CloseDB () {
  global $db;

  if($db)
  {
    $db->close();
  }    
}

?>
