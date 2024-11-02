from waitress import serve
    
from global_cluster_backend.wsgi import application
    
if __name__ == '__main__':
    serve(application, port='8000')