<?php if ( ! defined('PATH_PUBLIC')) die ('Bad requested!');
    require_once(PATH_PUBLIC . '/template/admin/header.php');
?>
<div id="wrapper">
	<div class="container">
	    <form method="post" action="admin.php">
	    <input type="hidden" name="c" value="song">
	    <input type="hidden" name="a" value="store">
	    <div class="row">   		
	    	<h2>Thêm Mới Bài Hát</h2>
	    </div>
		
	    <div class="row">   		
	    	<label>Tên Bài Hát </label>
	    </div>
	    <div class="row">
			<input type="text" name="name" id="" class="form-control">
	    </div>
	    <div class="row">   		
	    	<label>Lời Bài Hát</label>
	    </div>
	    <div class="row">
			<textarea name="lyrics" id="" class="form-control" cols="30" rows="10"></textarea>
	    </div>
		<div class="row"><label for="">Đường Dẫn</label></div>
		<div class="row"><input type="text" name="url" class="form-control"></div>
	    <div class="row">   		
	    	<label>Tên Albums</label>
	    </div>
		<div class="row">
	    <select class="form-control p-2 m-2" name="albums_id">
			<?php foreach ($list_album as $key => $value):
				$arr = (array) $value;?>
				<option value="<?php print_r($arr['id'])?>">
					<?php print_r($arr['name']);?>
				</option>
			<?php endforeach ?>
		</select>
		</div>

		 <div class="row">   		
	    	<label>Tên Ca Sĩ</label>
	    </div>
		<div class="row">
	    <select class="form-control p-2 m-2" name="singers_id">
			<?php foreach ($list_singer as $key=>$value):
				$arr = (array) $value;?>
				<option value="<?php print_r($arr['id'])?>">
					<?php print_r($arr['name']);?>
				</option>
			<?php endforeach ?>
		</select>
		</div>
	   
		<div class="row">   		
	    	<label>Tên Thể Loại</label>
	    </div>
		<div class="row">
	    <select class="form-control p-2 m-2" name="types_id">
			<?php foreach ($list_type as $key => $value):
				$arr = (array) $value;?>
				<option value="<?php print_r($arr['id'])?>">
					<?php print_r($arr['name']);?>
				</option>
			<?php endforeach ?>
		</select>
		</div>

	    <div class="row">   
	    	<button class="btn btn-primary p-2 m-2" type="submit">Create</button>
	    </div>
	    </form>
	</div>
</div>
<?php require_once(PATH_PUBLIC . '/template/admin/footer.php'); ?>