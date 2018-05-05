<?php if ( ! defined('PATH_SYSTEM')) die ('Bad requested!');

class singer_Controller extends Base_Controller
{
    /**
    * action index: show all singers
    * method: GET
    */
    public function index()
    {
        $this->model->load('Singer');
        $list_singer = $this->model->Singer->all();
        $data = array(
            'title' => 'index',
            'list_singer' => $list_singer
        );

        // Load view
        $this->view->load('singers/index', $data);
    }

    /**
    * action show: show a singer
    * method: GET
    */
    public function show()
    {
        $this->model->load('Singer');
        $singer = $this->model->Singer->findById($_GET['id']);
        $data = array(
            'title' => 'show',
            'singer' => $singer
        );

        // Load view
        $this->view->load('singers/show', $data);
    }

    /**
    * action create: create a singer
    * method: GET
    */
    public function create()
    {
        $this->view->load('singers/create');
    }

     /**
    * action store: save a singer to database
    * method: POST
    */
    public function store()
    {
        $this->model->load('Singer');
        $this->model->Singer->name = $_POST['name'];
        $this->model->Singer->image = $_POST['image'];
        $this->model->Singer->mota = $_POST['mota'];
        $this->model->Singer->save();

        go_back();
    }

    /**
    * action edit: show form edit a singer
    * method: GET
    */
    public function edit()
    {
        $this->model->load('singer');
        $singer = $this->model->singer->findById($_GET['id']);
        $data = array(
            'title' => 'edit',
            'singer' => $singer
        );

        // Load view
        $this->view->load('singers/edit', $data);
    }

    /**
    * action edit: update singer database
    * method: POST
    */
    public function update()
    {
        $this->model->load('Singer');
        $singer = $this->model->Singer->findById($_POST['id']);
        $singer->name = $_POST['name'];
        $singer->image = $_POST['image'];
        $singer->mota = $_POST['mota'];            ;
        $singer->update();
        go_back();
    }

    /**
    * action delete: show form edit a singer
    * method: GET
    */
    public function delete()
    {
        $this->model->load('Singer');
        $singer = $this->model->Singer->findById($_GET['id']);
        $singer->delete();

        go_back();
    }
}
