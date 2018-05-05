<?php if ( ! defined('PATH_PUBLIC')) die ('Bad requested!');
    require_once(PATH_PUBLIC . '/template/admin/header.php');
?>
<div class="container">
    <div class="row">
        <h3>Danh sach singer</h3>
    </div>
    <table class="table">
        <thead>
          <tr>
            <th>STT</th>
            <th>Tên Ca Sĩ</th>
            <th>Hình Ảnh</th>
            <th>Mô Tả</th>
            <th>Edit</th>
            <th>Delete</th>
          </tr>
        </thead>
        <tbody>
        <?php foreach ($list_singer as $singer) { ?>
          <tr>
            <td><?= increment_once($index); ?></td>
            <td><?=ucfirst($singer->name)?></td>
            <td><img src="<?= $singer->image; ?>" with=160 height=90 alt=""></td>
            <td><?= $singer->mota?></td>
            <td><a href="admin.php?c=singer&a=edit&id=<?= $singer->id; ?>">Edit</a></td>
            <td><a href="admin.php?c=singer&a=delete&id=<?= $singer->id; ?>">Delete</a</td>
          </tr>
        <?php } ?>
        </tbody>
    </table>
</div>
<?php require_once(PATH_PUBLIC . '/template/admin/footer.php'); ?>
