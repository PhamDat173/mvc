<?php if ( ! defined('PATH_PUBLIC')) die ('Bad requested!');
    require_once(PATH_PUBLIC . '/template/admin/header.php');
?>
<div id="wrapper">
	<div class="container">
	    <form method="post" action="admin.php">
	    <input type="hidden" name="id" value="<?=$song->id; ?>">
	    <input type="hidden" name="c" value="song">
	    <input type="hidden" name="a" value="update">
	    <div class="row">   		
	    	<h2>Chỉnh Sửa</h2>
	    </div>
	    <div class="row">   		
	    	<label>Tên Bài Hát :</label>
	    </div>
	    <div class="row">   		
	    	<input type="text" class="form-control " name="email" value="<?=$song->name; ?>">
	    </div>
	    <div class="row">   		
	    	<label>Lyrics</label>
	    </div>
	    <div class="row">   	
	    	<input type="text" class="form-control " name="text" value="<?=$song->lyrics; ?>">
	    </div>
		<div class="row">
			<label for="">Đường Dẫn</label>
		</div>
		<div class="row">
			<input type="text" class="form-control" name="url" id=""><?=$song->url?>
		</div>
	    <div class="row">   		
			<label>Ca si:</label>
		</div>
		<div class="row">
			<select class="form-control" name="singers_id">
				<option value="visible"><?=$song->singers_id;?></option>
			</select>
		</div>
		<div class="row">
			<lable>Album</lable>
		</div>
		<div class="row">
		<select name="albums_id" id="" class="form-control">
			<option value="visible"><?=$song->albums_id?></option>
		</select>
		</div>
	    
		<div class="row"><label for="">Thể Loại</label></div>
		<div class="row"><select class="form-control" name="types_id" id="">
		<option value="visible">
			<?=$song->types_id?>
		</option></select></div>

	    <div class="row">   
	    	<button class="btn btn-primary " type="submit">Apply</button>
	    </div>
	    </form>
	</div>
</div>
<?php require_once(PATH_PUBLIC . '/template/admin/footer.php'); ?>