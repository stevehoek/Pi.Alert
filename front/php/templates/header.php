<!-- ---------------------------------------------------------------------------
#  Pi.Alert
#  Open Source Network Guard / WIFI & LAN intrusion detector 
#
#  header.php - Front module. Common header to all the web pages 
#-------------------------------------------------------------------------------
#  GNU GPLv3
#--------------------------------------------------------------------------- -->

<?php
if (file_exists("darkmode")) {
    $ENABLED_DARKMODE = True;
}
?>

<!DOCTYPE html> 
<html>

<!-- ----------------------------------------------------------------------- -->
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>UniFi.Alert</title>

  <!-- Tell the browser to be responsive to screen width -->
  <meta content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" name="viewport">

  <!-- Bootstrap 3.3.7 -->
  <link rel="stylesheet" href="lib/AdminLTE/bower_components/bootstrap/dist/css/bootstrap.min.css">

  <!-- Font Awesome -->
  <link rel="stylesheet" href="lib/AdminLTE/bower_components/font-awesome/css/font-awesome.min.css">

  <!-- Ionicons -->
  <link rel="stylesheet" href="lib/AdminLTE/bower_components/Ionicons/css/ionicons.min.css">

  <!-- Theme style -->
  <link rel="stylesheet" href="lib/AdminLTE/dist/css/AdminLTE.min.css">

  <!-- AdminLTE Skins. We have chosen the skin-blue for this starter
        page. However, you can choose any other skin. Make sure you
        apply the skin class to the body tag so the changes take effect. -->
  <link rel="stylesheet" href="lib/AdminLTE/dist/css/skins/skin-blue.min.css">

  <!-- Pi.Alert CSS -->
  <link rel="stylesheet" href="css/pialert.css">

  <!-- Dark-Mode Patch -->
  <?php
  if ($ENABLED_DARKMODE === True) {
     echo '<link rel="stylesheet" href="css/dark-patch.css">';
     $BACKGROUND_IMAGE='style="background-image: url(\'img/boxed-bg-dark.png\');"';
  } else {
     $BACKGROUND_IMAGE='style="background-image: url(\'img/background.png\');"';
  }
  ?>

  <!-- HTML5 Shim and Respond.js IE8 support of HTML5 elements and media queries -->
  <!-- WARNING: Respond.js doesn't work if you view the page via file:// -->
  <!--[if lt IE 9]>
    <script src="https://oss.maxcdn.com/html5shiv/3.7.3/html5shiv.min.js"></script>
    <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
  <![endif]-->

  <!-- Google Font -->
  <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,600,700,300italic,400italic,600italic">

  <!-- Page Icon -->
  <link rel="icon" type="image/png" sizes="160x160" href="img/pialertLogoGray80.png" />
</head>

<!-- ----------------------------------------------------------------------- -->
<!-- Layout Boxed Blue -->
<body class="hold-transition skin-blue layout-boxed sidebar-mini" <?php echo $BACKGROUND_IMAGE;?>>
<!-- Site wrapper -->
<div class="wrapper">

  <!-- Main Header -->
  <header class="main-header">

<!-- ----------------------------------------------------------------------- -->
    <!-- Logo -->
    <a href="." class="logo">
      <!-- mini logo for sidebar mini 50x50 pixels -->
      <span class="logo-mini">U<b>a</b></span>
      <!-- logo for regular state and mobile devices -->
      <span class="logo-lg">UniFi<b>.Alert</b></span>
    </a>

<!-- ----------------------------------------------------------------------- -->
    <!-- Header Navbar -->
    <nav class="navbar navbar-static-top" role="navigation">
      <!-- Sidebar toggle button-->
      <a href="#" class="sidebar-toggle" data-toggle="push-menu" role="button">
        <span class="sr-only">Toggle navigation</span>
      </a>
      <!-- Navbar Right Menu -->
      <div class="navbar-custom-menu">
        <ul class="nav navbar-nav">

          <!-- Last Scan Time and Duration -->
          <li><a style="pointer-events:none;" class="hidden-xs">Last Scan:</a></li>
          <li><a id="lastScanTime" style="pointer-events:none;" class="hidden-xs"></a></li>
          <li><a style="pointer-events:none;" class="hidden-xs">for</a></li>
          <li><a id="lastScanDuration" style="pointer-events:none;font-weight: bold;" class="hidden-xs"></a></li>
          <li><a style="pointer-events:none;" class="hidden-xs">on</a></li>

          <!-- Server Name -->
          <li><a style="pointer-events:none;" class="hidden-xs"><?php echo gethostname(); ?></a></li>

          <!-- Refresh -->
          <li><a href="javascript:forceScan(15);"><i class="fa fa-retweet"></i><span> Scan</span></a></li>

          <!-- Refresh -->
          <li><a href="javascript:showLatestReport(15);"><i class="fa fa-inbox"></i><span></span></a></li>

          <!-- Header right info -->
          <li class="dropdown user user-menu">
            <!-- Menu Toggle Button -->
            <a href="#" class="dropdown-toggle" data-toggle="dropdown">
              <!-- The user image in the navbar-->
              <img src="img/pialertLogoWhite.png" class="user-image" style="border-radius: initial" alt="Pi.Alert Logo">
              <!-- hidden-xs hides the username on small devices so only the image appears. -->
              <span class="hidden-xs">UniFi.Alert</span>
            </a>
            <ul class="dropdown-menu">
              <!-- The user image in the menu -->
              <li class="user-header">
                <img src="img/pialertLogoWhite.png" class="img-circle" alt="Pi.Alert Logo" style="border-color:transparent">
                <p>
                  UniFi.Alert 
                  <small>Open Source Network Monitor</small>
                </p>
              </li>

              <!-- Menu Body -->
              <li class="user-body">
                <div class="row">
                  <div class="col-xs-4 text-center">
                    <a target="_blank" href="https://github.com/stevehoek/Pi.Alert">GitHub UniFi.Alert</a>
                  </div>
                  <div class="col-xs-4 text-center">
                    <a target="_blank" href="https://github.com/stevehoek/Pi.Alert/issues">Support</a>
                  </div>
                  <div class="col-xs-4 text-center">
                    <a target="_blank" href="https://github.com/stevehoek/Pi.Alert/blob/main/LICENSE.txt">GNU GPLv3</a>
                  </div>
                  <!--
                  <div class="col-xs-4 text-center">
                    <a href="#">Updates</a>
                  </div>
                  -->
                </div>
                <!-- /.row -->
              </li>
            </ul>
          </li>
        </ul>
      </div>
    </nav>
  </header>

<!-- ----------------------------------------------------------------------- -->
  <!-- Left side column. contains the logo and sidebar -->
  <aside class="main-sidebar">

    <!-- sidebar: style can be found in sidebar.less -->
    <section class="sidebar">

      <!-- Sidebar user panel (optional) -->
      <div class="user-panel">
        <a href="." class="logo">
          <img src="img/pialertLogoGray80.png" class="img-responsive" alt="Pi.Alert Logo"/>
        </a>
      </div>

      <!-- search form (Optional) -->
        <!-- DELETED -->

      <!-- Sidebar Menu -->
      <ul class="sidebar-menu" data-widget="tree">
<!--
        <li class="header">MAIN MENU</li>
-->

<li class=" <?php if (in_array (basename($_SERVER['SCRIPT_NAME']), array('devices.php', 'deviceDetails.php') ) ){ echo 'active'; } ?>">
          <a href="devices.php"><i class="fa fa-laptop"></i> <span>Devices</span>
            <small class="label pull-right bg-blue" id="header_dev_count_all"></small>
            <small class="label pull-right bg-green" id="header_dev_count_on"></small>
            <small class="label pull-right bg-gray-active" id="header_dev_count_off"></small>
            <small class="label pull-right bg-red" id="header_dev_count_down"></small>
            <small class="label pull-right bg-yellow" id="header_dev_count_new"></small>
          </a>
        </li>
        
<!--
         <li><a href="devices.php?status=favorites"><i class="fa fa-star"></i> <span>Favorites Devices</span></a></li>
-->
        <li class=" <?php if (in_array (basename($_SERVER['SCRIPT_NAME']), array('presence.php') ) ){ echo 'active'; } ?>">
          <a href="presence.php"><i class="fa fa-calendar"></i> <span>Presence</span></a>
        </li>

        <li class=" <?php if (in_array (basename($_SERVER['SCRIPT_NAME']), array('events.php') ) ){ echo 'active'; } ?>">
          <a href="events.php"><i class="fa fa-bolt"></i> <span>Events</span></a>
        </li>

<!--
        <li class="treeview">
          <a href="#"><i class="fa fa-link"></i> <span>Config</span>
            <span class="pull-right-container">
                <i class="fa fa-angle-left pull-right"></i>
              </span>
          </a>
          <ul class="treeview-menu">
            <li class=" <?php if (in_array (basename($_SERVER['SCRIPT_NAME']), array('scancycles.php', 'scancyclesDetails.php') ) ){ echo 'active'; } ?>">
              <a href="scancycles.php"><i class="fa fa-link"></i> <span>Scan Cycles</span></a>
            </li>
            <li><a href="#">Cron Status</a></li>
            <li><a href="#">Current IP</a></li>
          </ul>
        </li>
-->
      </ul>

      <!-- /.sidebar-menu -->
    </section>
    <!-- /.sidebar -->
  </aside>
