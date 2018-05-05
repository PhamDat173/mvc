<?php
class Singer_Model{
  public $id;
  public $name;
  public $image;
  public $mota;

  public function all(){
    $conn = FT_Database::instance()->getConnection();
    $sql = 'select * from singers';
    $result = mysqli_query($conn, $sql);
    $list_singer = array();

    if(!$result)
      die('Error: '.mysqli_query_error());

    while ($row = mysqli_fetch_assoc($result)){
            $singer = new Singer_Model();
            $singer->id = $row['id'];
            $singer->name = $row['name'];
            $singer->image=$row['image'];
            $singer->mota = $row['mota'];
            $list_singer[] = $singer;
        }

        return $list_singer;
  }

  public function save(){
    $conn = FT_Database::instance()->getConnection();
    $stmt = $conn->prepare("INSERT INTO singers (name, mota,image)
      VALUES (?,?,?)");
    $stmt->bind_param("sss", $this->name,$this->image, $this->mota);
    $rs = $stmt->execute();
    $this->id = $stmt->insert_id;
    $stmt->close();
    return $rs;
  }

  public function findById($id){
    $conn = FT_Database::instance()->getConnection();
    $sql = 'select * from singers where id='.$id;
    $result = mysqli_query($conn, $sql);

    if(!$result)
      die('Error: ');

    $row = mysqli_fetch_assoc($result);
        $singer = new Singer_Model();
            $singer->id = $row['id'];
            $singer->name = $row['name'];
            $singer->image=$row['image'];
            $singer->mota = $row['mota'];

        return $singer;
  }

  public function delete(){
    $conn = FT_Database::instance()->getConnection();
    $sql = 'delete from singers where id='.$this->id;
    $result = mysqli_query($conn, $sql);

    return $result;
  }

  public function update(){
    $conn = FT_Database::instance()->getConnection();
    $stmt = $conn->prepare("UPDATE singers SET name=?,image=?, mota=? WHERE id=?");
    $stmt->bind_param("sssi", $this->name,$this->image, $this->mota, $_POST['id']);
    $stmt->execute();
    $stmt->close();
  }
}
?>
