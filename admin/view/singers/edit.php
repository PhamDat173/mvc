<?php if ( ! defined('PATH_PUBLIC')) die ('Bad requested!');
    require_once(PATH_PUBLIC . '/template/admin/header.php');
?>
<div id="wrapper">
	<div class="container">
	    <form method="post" action="admin.php">
	    <input type="hidden" name="id" value="<?php echo $singer->id; ?>">
	    <input type="hidden" name="c" value="singer">
	    <input type="hidden" name="a" value="update">
	    <div class="row">   		
	    	<h2>Edit singer</h2>
	    </div>
	    <div class="row">   		
	    	<label>Email:</label>
	    </div>
	    <div class="row">   		
	    	<input type="text" class="form-control p-2 m-2" name="name" value="<?php echo $singer->name; ?>">
	    </div>
	    <div class="row">   		
	    	<label>Mô Tả</label>
	    </div>
	    <div class="row">   	
	    	<input type="text" class="form-control p-2 m-2" name="mota" value="<?php echo $singer->mota; ?>">
	    </div>
	    <div class="row">   		
	    	<label>Hình Ảnh</label>
	    </div>
	    <div class="row">   	
	    	<input type="text" class="form-control p-2 m-2" name="image" value="<?php echo $singer->image; ?>">
	    </div>
	    
	    <div class="row">   
	    	<button class="btn btn-primary p-2 m-2" type="submit">Apply</button>
	    </div>
	    </form>
	</div>
</div>
<?php require_once(PATH_PUBLIC . '/template/admin/footer.php'); ?>