/* -----------------------------------------------------------------------------
*  Pi.Alert
*  Open Source Network Guard / WIFI & LAN intrusion detector 
*
*  pialert_common.js - Front module. Common Javascript functions
*-------------------------------------------------------------------------------
*  GNU GPLv3
----------------------------------------------------------------------------- */

// -----------------------------------------------------------------------------
var timerRefreshData = ''
var modalCallbackFunction = '';


// -----------------------------------------------------------------------------
function showModal (title, message, btnCancel, btnOK, callbackFunction) {
  // set captions
  $('#modal-title').html      (title);
  $('#modal-message').html    (message);
  $('#modal-cancel').html     (btnCancel);
  $('#modal-OK').html         (btnOK);
  modalCallbackFunction =     callbackFunction;

  // Show modal
  $('#modal-warning').modal('show');
}

// -----------------------------------------------------------------------------
function modalOK () {
  // Hide modal
  $('#modal-warning').modal('hide');

  // timer to execute function
  window.setTimeout( function() {
    window[modalCallbackFunction]();
  }, 100);
}

// -----------------------------------------------------------------------------
function showMessage (textMessage="") {
  if (textMessage.toLowerCase().includes("error")  ) {
    // show error
    alert (textMessage);
  } else {
    // show temporal notification
    $("#alert-message").html (textMessage);
    $("#notification").fadeIn(1, function () {
      window.setTimeout( function() {
        $("#notification").fadeOut(500)
      }, 3000);
    } );
  }
}


// -----------------------------------------------------------------------------
function setParameter (parameter, value) {
  // Retry
  $.get('php/server/parameters.php?action=set&parameter=' + parameter +
    '&value='+ value,
  function(data) {
    if (data != "OK") {
      // Retry
      sleep (200);
      $.get('php/server/parameters.php?action=set&parameter=' + parameter +
        '&value='+ value,
      function(data) {
        if (data != "OK") {
         // alert (data);
        } else {
        // alert ("OK. Second attempt");
        };
      } );
    };
  } );
}


// -----------------------------------------------------------------------------
function sleep(milliseconds) {
  const date = Date.now();
  let currentDate = null;
  do {
    currentDate = Date.now();
  } while (currentDate - date < milliseconds);
}


// -----------------------------------------------------------------------------
function translateHTMLcodes (text) {
  if (text == null) {
    return null;
  }
  var text2 = text.replace(new RegExp(' ', 'g'), "&nbsp");
  text2 = text2.replace(new RegExp('<', 'g'), "&lt");
  return text2;
}


// -----------------------------------------------------------------------------
function stopTimerRefreshData () {
  try {
    clearTimeout (timerRefreshData); 
  } catch (e) {}
}


// -----------------------------------------------------------------------------
function newTimerRefreshData (refeshFunction) {
  timerRefreshData = setTimeout (function() {
    refeshFunction();
  }, 5000);
}


// -----------------------------------------------------------------------------
function debugTimer () {
  $('#pageTitle').html (new Date().getSeconds());
}


// -----------------------------------------------------------------------------
function refreshDevices (cycle) {
  // show temporal notification
  time = (cycle * 2);
  msg = "Refreshing.  Please wait up to " + time + " seconds...";
  $("#alert-message").html(msg);
  $("#notification").fadeIn(1, function() {

    // send command to server
    $.get('php/server/commands.php?action=refreshDevices&cycle=' + cycle,
    function(data) {
      $("#notification").fadeOut(500);
      if (data != "") {
        console.log(data);
        msg = "<pre>"+data+"</pre>"
        showModal ('Pi.Alert Report', msg,'Cancel', 'OK', 'refreshPage');
      }
    } );
  } );
}

function refreshPage () {
  window.location.href = window.location.href;
}


// -----------------------------------------------------------------------------
function showLatestReport (cycle) {
  // show temporal notification
  $("#alert-message").html("Fetching latest Report...");
  $("#notification").fadeIn(1, function() {
    // send command to server
    $.get('php/server/commands.php?action=showLatestReport&cycle=' + cycle,
    function(data) {
      $("#notification").fadeOut(500);
      if (data != "") {
        console.log(data);
        msg = "<pre>"+data+"</pre>"
        showModal ('Pi.Alert Report', msg,'Cancel', 'OK', 'refreshPage');
      }
    } );
  } );
}
