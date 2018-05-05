<?php if ( ! defined('PATH_SYSTEM')) die ('Bad requested!');

class type_Controller extends Base_Controller
{
    /**
    * action index: show all types
    * method: GET
    */
    public function index()
    {
        $this->model->load('type');
        $list_type = $this->model->type->all();
        $data = array(
            'title' => 'index',
            'list_type' => $list_type
        );

        // Load view
        $this->view->load('types/index', $data);
    }

    /**
    * action show: show a type
    * method: GET
    */
    public function show()
    {
        $this->model->load('type');
        $type = $this->model->type->findById($_GET['id']);
        $data = array(
            'title' => 'show',
            'type' => $type
        );

        // Load view
        $this->view->load('types/show', $data);
    }

    /**
    * action create: create a type
    * method: GET
    */
    public function create()
    {
        $this->view->load('types/create');
    }

     /**
    * action store: save a type to database
    * method: POST
    */
    public function store()
    {
        $this->model->load('type');
        $this->model->type->name = $_POST['name'];
        $this->model->type->save();

        go_back();
    }

    /**
    * action edit: show form edit a type
    * method: GET
    */
    public function edit()
    {
        $this->model->load('Type');
        $type = $this->model->Type->findById($_GET['id']);
        $data = array(
            'title' => 'edit',
            'type' => $type
        );

        // Load view
        $this->view->load('types/edit', $data);
    }

    /**
    * action edit: update type database
    * method: POST
    */
    public function update()
    {
        $this->model->load('type');
        $type = $this->model->type->findById($_POST['id']);
        $type->name = $_POST['name'];       ;
        $type->update();

        go_back();
    }

    /**
    * action delete: show form edit a type
    * method: GET
    */
    public function delete()
    {
        $this->model->load('type');
        $type = $this->model->type->findById($_GET['id']);
        $type->delete();

        go_back();
    }
}
