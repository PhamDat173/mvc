<?php
 class Song_Model{
  public $id;
  public $singers_id;
  public $types_id;
  public $albums_id;
  public $url;
  public $name;
  public $lyrics;

  public function all(){
    $conn = FT_Database::instance()->getConnection();
    $sql = 'SELECT songs.id,songs.name,songs.url,songs.lyrics,
    singers.name as singers_name,
    albums.name as albums_name,
    types.name as types_name
     FROM (((songs
     INNER JOIN singers
     ON songs.singers_id = singers.id)
     INNER JOIN  albums ON songs.albums_id=albums.id)
     INNER JOIN  types ON songs.types_id=types.id)';
    $result = mysqli_query($conn, $sql);
    $list_song = array();

    if(!$result)
      die('Error: '.mysqli_query_error());

    while ($row = mysqli_fetch_assoc($result)){
            $song = new Song_Model();
            $song->id = $row['id'];
            $song->name = $row['name'];
            $song->lyrics = $row['lyrics'];
            $song->url = $row['url'];
            $song->albums_id=$row['albums_name'];
            $song->singers_id = $row['singers_name'];
            $song->types_id = $row['types_name'];
            $list_song[] = $song;
        }

        return $list_song;
  }

  public function save(){
    $conn = FT_Database::instance()->getConnection();
    $stmt = $conn->prepare("INSERT INTO songs (name,lyrics,url,albums_id,singers_id,types_id)
      VALUES (?,?,?,?,?,?)");
    $stmt->bind_param("sssiii",$this->name,$this->lyrics,$this->url,$this->albums_id,$this->singers_id,$this->types_id);
    $rs = $stmt->execute();
    $this->id = $stmt->insert_id;
    $stmt->close();
    return $rs;
  }

  public function findById($id){
    $conn = FT_Database::instance()->getConnection();
    $sql = 'select * from songs where id='.$id;
    $result = mysqli_query($conn, $sql);

    if(!$result)
      die('Error: ');

    $row = mysqli_fetch_assoc($result);
        $song = new Song_Model();
            $song->id = $row['id'];
            $song->name = $row['name'];
            $song->lyrics = $row['lyrics'];
            $song->url=$row['url'];
            $song->albums_id=$row['albums_id'];
            $song->singers_id = $row['singers_id'];
            $song->types_id = $row['types_id'];

        return $song;
  }

  public function delete(){
    $conn = FT_Database::instance()->getConnection();
    $sql = 'delete from songs where id='.$this->id;
    $result = mysqli_query($conn, $sql);

    return $result;
  }

  public function update(){
    $conn = FT_Database::instance()->getConnection();
    $stmt = $conn->prepare("UPDATE songs SET singers_id=?,albums_id=?,types_id=?,name=?,url=?,lyrics=?
      WHERE id=?");

    $stmt->bind_param("iiisssi", $this->albums_id,$this->singers_id, $this->types_id, $this->name,$this->url, $this->lyrics, $_POST['id']);
    $stmt->execute();
    $stmt->close();
  }
}
?>
