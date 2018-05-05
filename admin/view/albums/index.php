<?php if ( ! defined('PATH_PUBLIC')) die ('Bad requested!');
    require_once(PATH_PUBLIC . '/template/admin/header.php');
?>
<div class="container">
    <div class="row">
        <h3>Danh sach album</h3>
    </div>
    <table class="table">
        <thead>
          <tr>
            <th>STT</th>
            <th>Tên Album</th>
            <th>Hình Ảnh</th>
            <th>Edit</th>
            <th>Delete</th>
          </tr>
        </thead>
        <tbody>
        <?php foreach ($list_album as $album) { ?>
          <tr>
            <td><?= increment_once($index); ?></td>
            <td><?=ucfirst($album->name)?></td>
            <td><img src="<?= $album->image; ?>" with=160 height=90 alt=""></td>
            <td><a href="admin.php?c=album&a=edit&id=<?= $album->id; ?>">Edit</a></td>
            <td><a href="admin.php?c=album&a=delete&id=<?= $album->id; ?>">Delete</a</td>
          </tr>
        <?php } ?>
        </tbody>
    </table>
</div>
<?php require_once(PATH_PUBLIC . '/template/admin/footer.php'); ?>
