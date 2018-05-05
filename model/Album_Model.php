<?php
class Album_Model{
  public $id;
  public $name;
  public $image;

  public function all(){
    $conn = FT_Database::instance()->getConnection();
    $sql = 'select * from albums';
    $result = mysqli_query($conn, $sql);
    $list_album = array();

    if(!$result)
      die('Error: '.mysqli_query_error());

    while ($row = mysqli_fetch_assoc($result)){
            $album = new Album_Model();
            $album->id = $row['id'];
            $album->name = $row['name'];
            $album->image = $row['image'];
            $list_album[] = $album;
        }

        return $list_album;
  }

  public function save(){
    $conn = FT_Database::instance()->getConnection();
    $stmt = $conn->prepare("INSERT INTO albums (name, image)
      VALUES (?, ?)");
    $stmt->bind_param("ss", $this->name , $this->image);
    $rs = $stmt->execute();
    $this->id = $stmt->insert_id;
    $stmt->close();
    return $rs;
  }

  public function findById($id){
    $conn = FT_Database::instance()->getConnection();
    $sql = 'select * from albums where id='.$id;
    $result = mysqli_query($conn, $sql);

    if(!$result)
      die('Error: ');

    $row = mysqli_fetch_assoc($result);
        $album = new Album_Model();
            $album->id = $row['id'];
            $album->name = $row['name'];
            $album->image = $row['image'];

        return $album;
  }

  public function delete(){
    $conn = FT_Database::instance()->getConnection();
    $sql = 'delete from albums where id='.$this->id;
    $result = mysqli_query($conn, $sql);

    return $result;
  }

  public function update(){
    $conn = FT_Database::instance()->getConnection();
    $stmt = $conn->prepare("UPDATE albums SET name=?,image=? WHERE id=?");
    $stmt->bind_param("ssi", $this->name,$this->image ,$_POST['id']);
    $stmt->execute();
    $stmt->close();
  }
}
?>
