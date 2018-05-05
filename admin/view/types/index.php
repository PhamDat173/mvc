<?php if ( ! defined('PATH_PUBLIC')) die ('Bad requested!');
    require_once(PATH_PUBLIC . '/template/admin/header.php');
?>
<div class="container">
    <div class="row">
        <h3>Thể Loại</h3>
    </div>
    <table class="table">
        <thead>
          <tr>
            <th>STT</th>
            <th>Tên </th>
            <th>Edit</th>
            <th>Delete</th>
          </tr>
        </thead>
        <tbody>
        <?php foreach ($list_type as $type) { ?>
          <tr>
            <td><?= increment_once($index); ?></td>
            <td><?= $type->name; ?></td>
            <td><a href="admin.php?c=type&a=edit&id=<?= $type->id; ?>">Edit</a></td>
            <td><a href="admin.php?c=type&a=delete&id=<?= $type->id; ?>">Delete</a</td>
          </tr>
        <?php } ?>
        </tbody>
    </table>
</div>
<?php require_once(PATH_PUBLIC . '/template/admin/footer.php'); ?>
