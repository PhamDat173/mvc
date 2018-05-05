<?php if ( ! defined('PATH_SYSTEM')) die ('Bad requested!');
class song_Controller extends Base_Controller
{
    /**
    * action index: show all songs
    * method: GET
    */
    public function index()
    {        
        $this->model->load('song');
        $list_song=$this->model->song->all();
        $data=array(
            'title'=>'index',
            'list_song'=>$list_song
        );
       
        $this->view->load('songs/index', $data);
    }
    /**
    * action show: show a song
    * method: GET
    */
    public function show()
    {        
        $this->model->load('Song');
        $song=$this->model->Song->findById($_GET['id']);
        $data=array(
            'title'=>'show',
            'song'=>$song
        );
        // Load view
        $this->view->load('songs/show', $data);
    }
    /**
    * action create: create a song
    * method: GET
    */
    public function create()
    {        
        $this->model->load('Album');
        $this->model->load('singer');
        $this->model->load('type');
        $list_album=$this->model->Album->all();
        $list_singer=$this->model->singer->all();
        $list_type=$this->model->type->all();
        $data=array(
            'title'=>'index',
            'list_album'=>$list_album,
            'list_singer'=>$list_singer,
            'list_type'=>$list_type
        );
        $this->view->load('songs/create',$data);
    }
     /**
    * action store: save a song to database
    * method: POST
    */
    public function store()
    {        
        $this->model->load('song');
        $this->model->song->name=$_POST['name'];
        $this->model->song->lyrics=$_POST['lyrics'];
        $this->model->song->url=$_POST['url'];
        $this->model->song->albums_id=$_POST['albums_id'];
        $this->model->song->singers_id=$_POST['singers_id'];
        $this->model->song->types_id=$_POST['types_id'];
        $this->model->song->save();
        go_back();
    }
    /**
    * action edit: show form edit a song
    * method: GET
    */
    public function edit()
    {        
        $this->model->load('song');
        $this->model->load('singer');
        $this->model->load('type');
        
        $song=$this->model->song->findById($_GET['id']);
        $singer=$this->model->singer->findById($_GET['id']);
        $type=$this->model->type->findById($_GET['id']);

        $data=array(
            'title'=>'edit',
            'song'=>$song
        );
        // Load view
        $this->view->load('songs/edit', $data);
    }
    /**
    * action edit: update song database
    * method: POST
    */
    public function update()
    {        
        $this->model->load('song');
        $song=$this->model->song->findById($_POST['id']);
        $song->singers_id=$_POST['singers_id'];
        $song->albums_id=$_POST['albums_id'];
        $song->types_id=$_POST['types_id'];
        $song->name=$_POST['name'];
        $song->lyrics=$_POST['lyrics'];
        $song->url=$_POST['url'];
        $song->update();
        go_back();
    }
    /**
    * action delete: show form edit a song
    * method: GET
    */
    public function delete()
    {        
        $this->model->load('song');
        $song=$this->model->song->findById($_GET['id']);
        $song->delete();
        go_back();
    }
}