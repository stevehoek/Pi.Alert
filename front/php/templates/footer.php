<!-- ---------------------------------------------------------------------------
#  Pi.Alert
#  Open Source Network Guard / WIFI & LAN intrusion detector 
#
#  footer.php - Front module. Common footer to all the web pages 
#-------------------------------------------------------------------------------
#  GNU GPLv3
#--------------------------------------------------------------------------- -->

  <!-- Main Footer -->
  <footer class="main-footer">
    <!-- Default to the left -->

    <!-- &copy; 2021 GNU GPLv3 -->
    <?php
      $conf_file = '../config/version.conf';
      $conf_data = parse_ini_file($conf_file);
      echo '<span style="display:inline-block; transform: rotate(180deg)">&copy;</span> '. $conf_data['VERSION_YEAR'] .' GNU GPLv3';
    ?>

    <!-- To the right -->
    <div class="pull-right no-hidden-xs">

    <!-- Pi.Alert  3.00  <small>(2021-03-08)</small> -->
    <?php
      $conf_file = '../config/version.conf';
      $conf_data = parse_ini_file($conf_file);
      echo 'UniFi.Alert&nbsp&nbsp'. $conf_data['VERSION'] .'&nbsp&nbsp<small>('. $conf_data['VERSION_DATE'] .')</small>';
    ?>
    </div>
  </footer>

<!-- ----------------------------------------------------------------------- -->
  <!-- Control Sidebar -->
    <!-- DELETED -->

</div>
<!-- ./wrapper -->

<!-- ----------------------------------------------------------------------- -->
<!-- REQUIRED JS SCRIPTS -->

<!-- jQuery 3 -->
  <script src="lib/AdminLTE/bower_components/jquery/dist/jquery.min.js"></script>

<!-- Bootstrap 3.3.7 -->
  <script src="lib/AdminLTE/bower_components/bootstrap/dist/js/bootstrap.min.js"></script>

<!-- AdminLTE App -->
  <script src="lib/AdminLTE/dist/js/adminlte.min.js"></script>

<!-- Optionally, you can add Slimscroll and FastClick plugins.
     Both of these plugins are recommended to enhance the
     user experience. -->

<!-- SlimScroll -->
  <!-- <script src="lib/AdminLTE/bower_components/jquery-slimscroll/jquery.slimscroll.min.js"></script> -->
<!-- FastClick -->
  <!-- <script src="lib/AdminLTE/bower_components/fastclick/lib/fastclick.js"></script>  -->

<!-- Pi.Alert -------------------------------------------------------------- -->
  <script src="js/pialert_common.js"></script>

  <script>
    function getDevicesTotalsBadge() {
      // get totals and put in boxes
      $.get('php/server/devices.php?action=getDevicesTotals', function(data) {
        var totalsDevicesbadge = JSON.parse(data);
        var unsetbadge = "";
        var offline = totalsDevicesbadge[0]-totalsDevicesbadge[1]-totalsDevicesbadge[3]-totalsDevicesbadge[4];
        
        if (totalsDevicesbadge[0] > 0) {$('#header_dev_count_all').html(totalsDevicesbadge[0].toLocaleString());} else {$('#header_dev_count_all').html(unsetbadge.toLocaleString());}
        if (totalsDevicesbadge[1] > 0) {$('#header_dev_count_on').html(totalsDevicesbadge[1].toLocaleString());} else {$('#header_dev_count_on').html(unsetbadge.toLocaleString());}
        if (totalsDevicesbadge[1] > 0) {$('#header_dev_count_off').html(offline.toLocaleString());} else {$('#header_dev_count_off').html(unsetbadge.toLocaleString());}
        if (totalsDevicesbadge[3] > 0) {$('#header_dev_count_new').html(totalsDevicesbadge[3].toLocaleString());} else {$('#header_dev_count_new').html(unsetbadge.toLocaleString());}
        if (totalsDevicesbadge[4] > 0) {$('#header_dev_count_down').html(totalsDevicesbadge[4].toLocaleString());} else {$('#header_dev_count_down').html(unsetbadge.toLocaleString());}
      } );
    }

    function updateTotals() {
      getDevicesTotalsBadge();
    }

    // Init functions
    updateTotals();

    // Start function timers
    setInterval(updateTotals, 60000);
  </script>


</body>
</html>
