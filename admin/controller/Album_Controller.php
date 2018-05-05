<?php if ( ! defined('PATH_SYSTEM')) die ('Bad requested!');

class album_Controller extends Base_Controller
{
    /**
    * action index: show all albums
    * method: GET
    */
    public function index()
    {
        $this->model->load('album');
        $list_album = $this->model->album->all();
        $data = array(
            'title' => 'index',
            'list_album' => $list_album
        );

        // Load view
        $this->view->load('albums/index', $data);
    }

    /**
    * action show: show a album
    * method: GET
    */
    public function show()
    {
        $this->model->load('Album');
        $album = $this->model->Album->findById($_GET['id']);
        $data = array(
            'title' => 'show',
            'album' => $album
        );

        // Load view
        $this->view->load('albums/show', $data);
    }

    /**
    * action create: create a album
    * method: GET
    */
    public function create()
    {
        $this->view->load('albums/create');
    }

     /**
    * action store: save a album to database
    * method: POST
    */
    public function store()
    {
        $this->model->load('album');
        $this->model->album->name = $_POST['name'];
        $this->model->album->image = $_POST['image'];
        $this->model->album->save();

        go_back();
    }

    /**
    * action edit: show form edit a album
    * method: GET
    */
    public function edit()
    {
        $this->model->load('album');
        $album = $this->model->album->findById($_GET['id']);
        $data = array(
            'title' => 'edit',
            'album' => $album
        );

        // Load view
        $this->view->load('albums/edit', $data);
    }

    /**
    * action edit: update album database
    * method: POST
    */
    public function update()
    {
        $this->model->load('album');
        $album = $this->model->album->findById($_POST['id']);
        $album->name = $_POST['name'];
        $album->image = $_POST['image'];         ;
        $album->update();

        go_back();
    }

    /**
    * action delete: show form edit a album
    * method: GET
    */
    public function delete()
    {
        $this->model->load('album');
        $album = $this->model->album->findById($_GET['id']);
        $album->delete();

        go_back();
    }
}
