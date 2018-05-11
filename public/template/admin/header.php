<!DOCTYPE html>
<html>
    <head>
        <title>Trang Chủ</title>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <link rel="stylesheet" type="text/css" href="public/css/css.css">
        <link rel="stylesheet" type="text/css" href="public/css/bootstrap.min.css">
        <link rel="stylesheet" type="text/css" href="public/css/custom.css">
        <script src="public/js/jquery-3.2.1.slim.min.js"></script>
        <script type="text/javascript" src="public/js/bootstrap.min.js"></script>
    </head>
    <body>
    <header>
    <div class="logo">
      <a href="index.php"><img src=".public\template\photo\logo.png" title="Magnetic" alt="Magnetic" width="100px" height="100px" /></a>
    </div><!-- end logo -->

    <div id="menu"></div>
    <nav>
      <ul>
        <li><a href="index.php" class="selected">Trang chủ</a></li>
        <li><a href="#">User</a>
          <ul class="submenu">
            <li><a href="admin.php?c=user&a=index">»Danh sách</a></li>
            <li><a href="admin.php?c=user&a=create">»Thêm mới</a></li>
          </ul>
        </li>
        <li><a href="#">Singer</a>
          <ul class="submenu">
            <li><a href="admin.php?c=singer&a=index">»Danh sách</a></li>
            <li><a href="admin.php?c=singer&a=create">»Thêm mới</a></li>
          </ul>
        </li>
        <li><a href="#">Album</a>
          <ul class="submenu">
            <li><a href="admin.php?c=album&a=index">»Danh sách</a></li>
            <li><a href="admin.php?c=album&a=create">»Thêm mới</a></li>
          </ul>
        </li>
        <li><a href="#">Song</a>
          <ul class="submenu">
            <li><a href="admin.php?c=song&a=index">»Danh sách</a></li>
            <li><a href="admin.php?c=song&a=create">»Thêm mới</a></li>
          </ul>
        </li>
        <li><a href="#">Type</a>
          <ul class="submenu">
            <li><a href="admin.php?c=type&a=index">»Danh sách</a></li>
            <li><a href="admin.php?c=type&a=create">»Thêm mới</a></li>
          </ul>
        </li>
        <li><a href="logout.php">Logout</a></li>
      </ul>
    </nav>

    <div class="footer clearfix">

      <div class="rights">
        <p>Copyright © 2018 by Phạm Đạt-Trịnh Quang-Huỳnh Thảo</p>
      </div><!-- end rights -->
    </div ><!-- end footer -->
  </header><!-- end header -->
</body>
</html>
