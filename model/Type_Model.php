<?php
class Type_Model{
  public $id;
  public $name;

  public function all(){
    $conn = FT_Database::instance()->getConnection();
    $sql = 'select * from types';
    $result = mysqli_query($conn, $sql);
    $list_album = array();

    if(!$result)
      die('Error: '.mysqli_query_error());

    while ($row = mysqli_fetch_assoc($result)){
            $type = new Type_Model();
            $type->id = $row['id'];
            $type->name = $row['name'];
            $list_type[] = $type;
        }

        return $list_type;
  }

  public function save(){
    $conn = FT_Database::instance()->getConnection();
    $stmt = $conn->prepare("INSERT INTO types (name)
      VALUES (?)");
    $stmt->bind_param("s", $this->name);
    $rs = $stmt->execute();
    $this->id = $stmt->insert_id;
    $stmt->close();
    return $rs;
  }

  public function findById($id){
    $conn = FT_Database::instance()->getConnection();
    $sql = 'select * from types where id='.$id;
    $result = mysqli_query($conn, $sql);

    if(!$result)
      die('Error: ');

    $row = mysqli_fetch_assoc($result);
        $type = new Type_Model();
            $type->id = $row['id'];
            $type->name = $row['name'];

        return $type;
  }

  public function delete(){
    $conn = FT_Database::instance()->getConnection();
    $sql = 'delete from types where id='.$this->id;
    $result = mysqli_query($conn, $sql);

    return $result;
  }

  public function update(){
    $conn = FT_Database::instance()->getConnection();
    $stmt = $conn->prepare("UPDATE types SET name=? WHERE id=?");
    $stmt->bind_param("si", $this->name, $_POST['id']);
    $stmt->execute();
    $stmt->close();
  }
}
?>
