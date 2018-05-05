<?php
class Comment_Model{
  public $id;
  public $content;
  public $song_id;
  public $user_id;

  public function all(){
    $conn = FT_Database::instance()->getConnection();
    $sql = 'select * from comments';
    $result = mysqli_query($conn, $sql);
    $list_comment = array();

    if(!$result)
      die('Error: '.mysqli_query_error());

    while ($row = mysqli_fetch_assoc($result)){
            $comment = new Comment_Model();
            $comment->id = $row['id'];
            $comment->content = $row['content'];
            $comment->song_id = $row['song_id'];
            $comment->user_id = $row['user_id'];

            $list_comment[] = $comment;
        }

        return $list_comment;
  }

  public function save(){
    $conn = FT_Database::instance()->getConnection();
    $stmt = $conn->prepare("INSERT INTO comments (content, song_id, user_id)
      VALUES (?, ?, ?)");
    $stmt->bind_param("sii", $this->content, $this->song_id, $this->user_id);
    $rs = $stmt->execute();
    $this->id = $stmt->insert_id;
    $stmt->close();
    return $rs;
  }

  public function findById($id){
    $conn = FT_Database::instance()->getConnection();
    $sql = 'select * from comments where id='.$id;
    $result = mysqli_query($conn, $sql);

    if(!$result)
      die('Error: ');

    $row = mysqli_fetch_assoc($result);
        $comment = new Comment_Model();
            $comment->id = $row['id'];
            $comment->content = $row['content'];
            $comment->song_id = $row['song_id'];
            $comment->user_id = $row['user_id'];

        return $comment;
  }

  public function delete(){
    $conn = FT_Database::instance()->getConnection();
    $sql = 'delete from comments where id='.$this->id;
    $result = mysqli_query($conn, $sql);

    return $result;
  }

  public function update(){
    $conn = FT_Database::instance()->getConnection();
    $stmt = $conn->prepare("UPDATE comments SET content=?, song_id=?, user_id=? WHERE id=?");
    $stmt->bind_param("siii", $this->content, $this->song_id, $this->user_id, $_POST['id']);
    $stmt->execute();
    $stmt->close();
  }
}
?>
