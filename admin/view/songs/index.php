<?php if ( ! defined('PATH_PUBLIC')) die ('Bad requested!');
    require_once(PATH_PUBLIC . '/template/admin/header.php');
?>
<div class="container">
    <div class="row">
        <legend>Danh Sách Bài Hát</legend>
    </div>
    <table class="table text-center">
        <thead>
          <tr>
            <th>STT</th>
            <th>Tên Bài Hát</th>
            <th>Ca Sĩ</th>
            <th>Album</th>
            <th>Thể Loại</th>
            <th>Edit</th>
            <th>Delete</th>
          </tr>
        </thead>
        <tbody>
        <?php foreach ($list_song as $song) { ?>
          <tr>
            <td><?= increment_once($index); ?></td>
            <td><?=ucfirst($song->name)?></td>
            <td><?=$song->singers_id?></td>
            <td><?=$song->albums_id?></td>
            <td><?=$song->types_id?></td>
            <td><a href="admin.php?c=song&a=edit&id=<?= $song->id; ?>">Edit</a></td>
            <td><a href="admin.php?c=song&a=delete&id=<?= $song->id; ?>">Delete</a</td>
          </tr>
        <?php } ?>
        </tbody>
    </table>
</div>
<?php require_once(PATH_PUBLIC . '/template/admin/footer.php'); ?>
