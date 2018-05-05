<?php if ( ! defined('PATH_SYSTEM')) die ('Bad requested!');

class User_Controller extends Base_Controller
{
    /**
    * action index: show all users
    * method: GET
    */
    public function index()
    {
        $this->model->load('User');
        $list_user = $this->model->User->all();
        $data = array(
            'title' => 'index',
            'list_user' => $list_user
        );

        // Load view
        $this->view->load('users/index', $data);
    }

    /**
    * action show: show a user
    * method: GET
    */
    public function show()
    {
        $this->model->load('User');
        $user = $this->model->User->findById($_GET['id']);
        $data = array(
            'title' => 'show',
            'user' => $user
        );

        // Load view
        $this->view->load('users/show', $data);
    }

    /**
    * action create: create a user
    * method: GET
    */
    public function create()
    {
        $this->view->load('users/create');
    }

     /**
    * action store: save a user to database
    * method: POST
    */
    public function store()
    {
        $this->model->load('User');
        $this->model->User->email = $_POST['email'];
        $this->model->User->password = $_POST['password'];
        $this->model->User->role = $_POST['role'];
        $this->model->User->status = $_POST['status'];
        $this->model->User->token = csrf_token();
        $this->model->User->save();

        go_back();
    }

    /**
    * action edit: show form edit a user
    * method: GET
    */
    public function edit()
    {
        $this->model->load('User');
        $user = $this->model->User->findById($_GET['id']);
        $data = array(
            'title' => 'edit',
            'user' => $user
        );

        // Load view
        $this->view->load('users/edit', $data);
    }

    /**
    * action edit: update user database
    * method: POST
    */
    public function update()
    {
        $this->model->load('User');
        $user = $this->model->User->findById($_POST['id']);
        $user->email = $_POST['email'];
        $user->password = $_POST['password'];
        $user->role = $_POST['role'];
        $user->status = $_POST['status'];             ;
        $user->update();

        go_back();
    }

    /**
    * action delete: show form edit a user
    * method: GET
    */
    public function delete()
    {
        $this->model->load('User');
        $user = $this->model->User->findById($_GET['id']);
        $user->delete();

        go_back();
    }
    public function login(){
        
    $this->view->load('login',$data);

    if(isset($_POST['login'])){
        $email=$_POST['email'];
        $password=$_POST['password'];
        $this->model->load('User');
        $id = $this->model->User->validate_login($email,$password); 
        redirect_to("localhost/mvc/admin.php?c=user&a=index");
            if ($admin_midlleware) {
                $token = $this->model->Users->generate_token($id);
                //redirect_to(URL . "controller=user&action=index&pages=0&token=$token");
                redirect_to("localhost/mvc/admin.php?c=user&a=index");
            } else {
                go_back();
            }
        } else {
           go_back();
        }
    }
}
