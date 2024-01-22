from fastapi import Depends, FastAPI, HTTPException, status, Response, Security, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes
from functools import lru_cache
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.sql import func
from sqlalchemy.sql.expression import case
from sqlalchemy import desc, asc
from uuid import uuid4
from pathlib import Path
from typing import Union
from datetime import datetime, timedelta
#---Imported for JWT example-----------
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, ValidationError
from typing_extensions import Annotated
import models
import schemas
from database import SessionLocal, engine 
import init_db
import config
from fpdf import FPDF
from fpdf_table import PDFTable, Align, add_image_local
import asyncio
import concurrent.futures

#-------FAKE DB------------------------
#User: julio:admin123 
#-------------------------------------
models.Base.metadata.create_all(bind=engine)

#Create resources for JWT flow
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(
	tokenUrl="token",
	scopes={"admin": "Add, edit and delete information.", "manager": "Create and read information.", "user": "Read information."}
)
#----------------------
#Create our main app
app = FastAPI()

#----SETUP MIDDLEWARES--------------------

# Allow these origins to access the API
origins = [	
	"http://my-app-4bad.onrender.com",
	"https://my-app-4bad.onrender.com",		
	"http://localhost",
	"http://localhost:8080",
	"https://localhost:8080",
	"http://localhost:5000",
	"https://localhost:5000",
	"http://localhost:3000",
	"https://localhost:3000",
	"http://localhost:8000",
	"https://localhost:8000",
]

# Allow these methods to be used
methods = ["GET", "POST", "PUT", "DELETE"]

# Only these headers are allowed
headers = ["Content-Type", "Authorization"]

app.add_middleware(
	CORSMiddleware,
	allow_origins=origins,
	allow_credentials=True,
	allow_methods=methods,
	allow_headers=headers,
	expose_headers=["*"]
)

ALGORITHM = config.ALGORITHM	
SECRET_KEY = config.SECRET_KEY
APP_NAME = config.APP_NAME
ACCESS_TOKEN_EXPIRE_MINUTES = config.ACCESS_TOKEN_EXPIRE_MINUTES
ADMIN_USER = config.ADMIN_USER
ADMIN_NAME = config.ADMIN_NAME
ADMIN_EMAIL = config.ADMIN_EMAIL
ADMIN_PASS = config.ADMIN_PASS

# Dependency
def get_db():
	db = SessionLocal()
	try:
		yield db
	finally:
		db.close()


#------CODE FOR THE JWT EXAMPLE----------
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db: Session, username: str):
	db_user = db.query(models.User).filter(models.User.username == username).first()	
	if db_user is not None:
		return db_user 

#This function is used by "login_for_access_token"
def authenticate_user(username: str, password: str,  db: Session = Depends(get_db)):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password): #secret
        return False
    return user
	
#This function is used by "login_for_access_token"
def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=30) #Si no se pasa un valor por usuario
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
	
#This function is used by "get currecnt active user" dependency security authentication
async def get_current_user(
			security_scopes: SecurityScopes, 
			token: Annotated[str, Depends(oauth2_scheme)],
			db: Session = Depends(get_db)):
	if security_scopes.scopes:
		authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
	else:
		authenticate_value = "Bearer"
		
	credentials_exception = HTTPException(
		status_code=status.HTTP_401_UNAUTHORIZED,
		detail="Could not validate credentials",
		headers={"WWW-Authenticate": "Bearer"},
	)
	try:
		payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
		username: str = payload.get("sub")
		if username is None:
			raise credentials_exception			
		token_scopes = payload.get("scopes", [])
		token_data = schemas.TokenData(scopes=token_scopes, username=username)
		
	except (JWTError, ValidationError):
		raise credentials_exception
			
		token_data = schemas.TokenData(username=username)
	except JWTError:
		raise credentials_exception
		
	user = get_user(db, username=token_data.username)
	if user is None:
		raise credentials_exception
		
	for user_scope in security_scopes.scopes:
		if user_scope not in token_data.scopes:
			raise HTTPException(
				status_code=status.HTTP_401_UNAUTHORIZED,
				detail="Not enough permissions",
				headers={"WWW-Authenticate": authenticate_value},
			)
			
	return user
	
async def get_current_active_user(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["admin"])]):  #, "manager", "user"
	if current_user.disable:
		print({"USER AUTENTICATED" : current_user.disable})
		print({"USER ROLES" : current_user.role})
		raise HTTPException(status_code=400, detail="Disable user")
	return current_user

#------------------------------------
@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(get_db)):
	user = authenticate_user(form_data.username, form_data.password, db)
	if not user:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Incorrect username or password",
			headers={"WWW-Authenticate": "Bearer"},
		)
	access_token_expires = timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
	print(form_data.scopes)
	print(user.role)
	access_token = create_access_token(
		data={"sub": user.username, "scopes": user.role},   #form_data.scopes
		expires_delta=access_token_expires
	)
	return {"access_token": access_token, "token_type": "Bearer"}
	
@app.get("/")
def index():
	return {"Application": "Hello from developers"}
	
@app.get("/get_restricted_user")
async def get_restricted_user(current_user: Annotated[schemas.User, Depends(get_current_active_user)]):
    return current_user
	
@app.get("/get_authenticated_admin_resources", response_model=schemas.User)
async def get_authenticated_admin_resources(current_user: Annotated[schemas.User, Security(get_current_active_user, scopes=["manager"])]):
    return current_user
	
@app.get("/get_authenticated_edition_resources", response_model=schemas.User)
async def get_authenticated_edition_resources(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])]):
    return current_user
	
@app.get("/get_user_status", response_model=schemas.User)
async def get_user_status(current_user: Annotated[schemas.User, Depends(get_current_user)]):
    return current_user
	
#########################
###   USERS ADMIN  ######
#########################
@app.post("/create_user_admin", status_code=status.HTTP_201_CREATED)  
async def create_user_admin(db: Session = Depends(get_db)): #Por el momento no tiene restricciones
	if db.query(models.User).filter(models.User.username == config.ADMIN_USER).first():
		db_user = db.query(models.User).filter(models.User.username == config.ADMIN_USER).first()
		if db_user is None:
			raise HTTPException(status_code=404, detail="User not found")	
		db.delete(db_user)	
		db.commit()
		
	db_user = models.User(
		username=config.ADMIN_USER, 
		full_name=config.ADMIN_NAME,
		email=config.ADMIN_EMAIL,
		role=["admin","manager","user"],
		disable=False,
		hashed_password=pwd_context.hash(config.ADMIN_PASS)		
	)
	db.add(db_user)
	db.commit()
	db.refresh(db_user)	
	return {f"User:": "Succesfully created"}
	
@app.post("/create_user/", status_code=status.HTTP_201_CREATED)  
async def create_user(current_user: Annotated[schemas.User, Depends(get_current_active_user)],
				user: schemas.UserInDB, db: Session = Depends(get_db)): 
	if db.query(models.User).filter(models.User.username == user.username).first() :
		raise HTTPException( 
			status_code=400,
			detail="The user with this email already exists in the system",
		)	
	db_user = models.User(
		username=user.username, 
		full_name=user.full_name,
		email=user.email,
		role=user.role,
		disable=False,
		hashed_password=pwd_context.hash(user.hashed_password)
	)
	db.add(db_user)
	db.commit()
	db.refresh(db_user)	
	return {f"User: {db_user.username}": "Succesfully created"}
	
@app.get("/read_users/", status_code=status.HTTP_201_CREATED) 
async def read_users(current_user: Annotated[schemas.User, Depends(get_current_active_user)],
		skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    	
	db_users = db.query(models.User).offset(skip).limit(limit).all()    
	return db_users

@app.put("/update_user/{username}", status_code=status.HTTP_201_CREATED) 
async def update_user(current_user: Annotated[schemas.User, Depends(get_current_active_user)], 
				username: str, new_user: schemas.UserUPD, db: Session = Depends(get_db)):
	db_user = db.query(models.User).filter(models.User.username == username).first()
	if db_user is None:
		raise HTTPException(status_code=404, detail="User not found")
	db_user.username=new_user.username
	db_user.full_name=new_user.full_name
	db_user.email=new_user.email		
	db.commit()
	db.refresh(db_user)	
	return db_user	
	
@app.put("/activate_user/{username}", status_code=status.HTTP_201_CREATED) 
async def activate_user(current_user: Annotated[schemas.User, Depends(get_current_active_user)],
				username: str, new_user: schemas.UserActivate, db: Session = Depends(get_db)):
	db_user = db.query(models.User).filter(models.User.username == username).first()
	if db_user is None:
		raise HTTPException(status_code=404, detail="User not found")
	db_user.disable=new_user.disable		
	db.commit()
	db.refresh(db_user)	
	return db_user	
	
@app.delete("/delete_user/{username}", status_code=status.HTTP_201_CREATED) 
async def delete_user(current_user: Annotated[schemas.User, Depends(get_current_active_user)],
				username: str, db: Session = Depends(get_db)):
	db_user = db.query(models.User).filter(models.User.username == username).first()
	if db_user is None:
		raise HTTPException(status_code=404, detail="User not found")	
	db.delete(db_user)	
	db.commit()
	return {"Deleted": "Delete User Successfuly"}
	
@app.put("/reset_password/{username}", status_code=status.HTTP_201_CREATED) 
async def reset_password(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
				username: str, password: schemas.UserPassword, db: Session = Depends(get_db)):
	db_user = db.query(models.User).filter(models.User.username == username).first()
	if db_user is None:
		raise HTTPException(status_code=404, detail="User not found")	
	db_user.hashed_password=pwd_context.hash(password.hashed_password)
	db.commit()
	db.refresh(db_user)	
	return {"Result": "Password Updated Successfuly"}
		
#######################
#CRUD for PROJECTS here
#######################

@app.post("/create_project/", status_code=status.HTTP_201_CREATED)  #, response_model=schemas.Project
async def create_project(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					project: schemas.Project, db: Session = Depends(get_db)):	
	try:
		db_project = db.query(models.Project).filter(models.Project.project_name == project.project_name).first()
		if db_project is None:
			db_project = models.Project(
				project_name=project.project_name, 
				desc_proj=project.desc_proj,			
				manager=project.manager,
				mail_manager=project.mail_manager,
				inidate_proj=func.now(),
				upddate_proj = func.now(),
				enddate_proj = project.enddate_proj,
				latitud=0,
				longitud=0,
				is_active=True, 
			)
			db.add(db_project)
			db.commit()
			db.refresh(db_project)	
			return db_project
	except IntegrityError as e:
		raise HTTPException(status_code=500, detail="Integrity error")
	except SQLAlchemyError as e: 
		raise HTTPException(status_code=405, detail="Unexpected error when creating project")

@app.get("/read_projects/", status_code=status.HTTP_201_CREATED)
async def read_projects(current_user: Annotated[schemas.User, Security(get_current_active_user, scopes=["admin"])],
				skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	projects = db.query(models.Project).offset(skip).limit(limit).all()    
	return projects
	
@app.get("/read_projects_by_user_email/{email}", status_code=status.HTTP_201_CREATED)
async def read_projects_by_user_email(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
								email: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	projects = db.query(models.Project).filter(models.Project.mail_manager == email).offset(skip).limit(limit).all()    
	return projects
	
@app.get("/read_projects_by_user/", status_code=status.HTTP_201_CREATED)
async def read_projects_by_user(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
								skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	projects = db.query(models.Project).filter(models.Project.mail_manager == current_user.mail_manager).offset(skip).limit(limit).all()    
	return projects
	
@app.put("/update_project/{project_id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
async def update_project(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					project_id: str, project: schemas.Project, db: Session = Depends(get_db)):
	db_project = db.query(models.Project).filter(models.Project.id == project_id).first()
	if db_project is None:
		raise HTTPException(status_code=404, detail="Project not found")
	db_project.project_name = project.project_name
	db_project.desc_proj = project.desc_proj
	db_project.manager = project.manager
	db_project.mail_manager = project.mail_manager
	db_project.upddate_proj = func.now()
	db.commit()
	db.refresh(db_project)	
	return db_project
	
@app.put("/update_project_date/{project_id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
async def update_project_date(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
						project_id: str, project: schemas.ProjectUpdDate, db: Session = Depends(get_db)):
	db_project = db.query(models.Project).filter(models.Project.id == project_id).first()
	if db_project is None:
		raise HTTPException(status_code=404, detail="Project not found")
	db_project.upddate_proj = func.now()
	db_project.enddate_proj = project.enddate_proj
	db.commit()
	db.refresh(db_project)	
	return db_project
	
@app.put("/activate_project/{id}", status_code=status.HTTP_201_CREATED) 
async def activate_project(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					id: str, project: schemas.LaborActive, db: Session = Depends(get_db)):
	db_project = db.query(models.Project).filter(models.Project.id == id).first()
	if db_project is None:
		raise HTTPException(status_code=404, detail="Project not found")
	db_project.is_active=project.is_active;		
	db.commit()
	db.refresh(db_project)	
	return {"Response": "Project successfully changed its status"}	

@app.delete("/delete_project/{project_id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
async def delete_project(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					project_id: str, db: Session = Depends(get_db)):
	db_project = db.query(models.Project).filter(models.Project.id == project_id).first()
	if db_project is None:
		raise HTTPException(status_code=404, detail="Project not found")	
	db.delete(db_project)	
	db.commit()
	return {"Deleted": "Delete Successfuly"}

#####################
#CRUD for LABORS here
#####################

@app.post("/create_labor/", status_code=status.HTTP_201_CREATED)  #, response_model=schemas.Project
async def create_labor(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					labor: schemas.Labor, db: Session = Depends(get_db)):		
	try:	
		db_parent_project = db.query(models.Project).filter(models.Project.id == labor.project_id).first()
		if 	db_parent_project is not None:		
			db_labor = models.Labor(
				type=labor.type,	
				desc_labor=labor.desc_labor,
				inidate_labor=func.now(),
				upddate_labor=func.now(),
				enddate_labor=labor.enddate_labor,
				project_id=labor.project_id, 
			)			
			
			db_parent_project.labors.append(db_labor)	
			db.add(db_labor)   	
			db.commit()
			db.refresh(db_labor)			
			return db_labor
		else:
			raise HTTPException(status_code=500, detail="Selected project for labor error")		
	except SQLAlchemyError as e: 
		raise HTTPException(status_code=405, detail="Unexpected error when creating labor")
		
@app.get("/read_labors/", status_code=status.HTTP_201_CREATED)  
async def read_labors(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
				skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	db_labors = db.query(
					models.Labor.id,
					models.Labor.type,
					models.Labor.desc_labor,
					models.Labor.inidate_labor,
					models.Labor.enddate_labor,
					models.Labor.is_active,
					models.Project.project_name,
					(models.Project.id).label('project_labor'),
				).join(models.Labor, models.Project.id == models.Labor.project_id
				).all()	
	return db_labors
	
@app.get("/read_labors_by_project_id/{project_id}", status_code=status.HTTP_201_CREATED)  
async def read_labors_by_project_id(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
							project_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	db_labors = db.query(
					models.Labor.id,
					models.Labor.type,
					models.Labor.desc_labor,
					models.Labor.inidate_labor,
					models.Labor.enddate_labor,
					models.Labor.is_active,
					models.Project.project_name,
					(models.Project.id).label('project_labor'),
				).join(models.Labor, models.Project.id == models.Labor.project_id
				).filter_by(project_id = project_id
				).all()	
	return db_labors
	
@app.put("/update_labor/{labor_id}", status_code=status.HTTP_201_CREATED) 
async def update_labor(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					labor_id: str, upd_labor: schemas.LaborUPD, db: Session = Depends(get_db)):
	db_labor = db.query(models.Labor).filter(models.Labor.id == labor_id).first()
	if db_labor is None:
		raise HTTPException(status_code=404, detail="Labor category not found")
	db_labor.desc_labor=upd_labor.desc_labor
	db_labor.type=upd_labor.type
	db_labor.upddate_labor=func.now()
	db.commit()
	db.refresh(db_labor)	
	return db_labor

@app.put("/update_labor_date/{labor_id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
async def update_labor_date(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					labor_id: str, labor: schemas.LaborUpdDate, db: Session = Depends(get_db)):
	db_labor = db.query(models.Labor).filter(models.Labor.id == labor_id).first()
	if db_labor is None:
		raise HTTPException(status_code=404, detail="Labor not found")
	db_labor.upddate_labor = func.now()
	db_labor.enddate_labor = labor.enddate_labor
	db.commit()
	db.refresh(db_labor)	
	return db_labor
	
@app.put("/activate_labor/{id}", status_code=status.HTTP_201_CREATED) 
async def activate_labor(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					id: str, labor: schemas.LaborActive, db: Session = Depends(get_db)):
	db_labor = db.query(models.Labor).filter(models.Labor.id == id).first()
	if db_labor is None:
		raise HTTPException(status_code=404, detail="Labor not found")
	db_labor.is_active=labor.is_active;		
	db.commit()
	db.refresh(db_labor)	
	return {"Response": "Labor successfully changed its status"}	
	
@app.delete("/delete_labor/{labor_id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
async def delete_labor(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					labor_id: str, db: Session = Depends(get_db)):
	db_labor = db.query(models.Labor).filter(models.Labor.id == labor_id).first()
	if db_labor is None:
		raise HTTPException(status_code=404, detail="Labor not found")	
	db.delete(db_labor)	
	db.commit()
	return {"Deleted": "Delete Successfuly"}

#########################	
#------TASK-------------
#########################

@app.post("/create_task/", status_code=status.HTTP_201_CREATED) 
async def create_task(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
				task: schemas.Task, db: Session = Depends(get_db)):		
	try:	
		tasks_in_db = db.query(
							models.Labor.type,
							models.Task.id,
							models.Task.description,							
							(models.Labor.id).label('labor_parent')
							).join(models.Task, models.Labor.id == models.Task.labor_task_id
						).filter_by(description = task.description
						).filter_by(labor_task_id = task.labor_task_id
						).all()	
		if 	len(tasks_in_db) == 0:		
			db_task = models.Task(
				description=task.description,	
				mechanicals=task.mechanicals,
				hour=task.hour,  
				task_price=task.task_price,
				hour_men=(task.hour * task.mechanicals),
				inidate_task=func.now(),
				upddate_task=func.now(),
				enddate_task=task.enddate_task,
				is_active=True,
				labor_task_id=task.labor_task_id,
			)			
			db_parent_labor = db.query(models.Labor).filter(models.Labor.id == task.labor_task_id).first()
			db_parent_labor.tasks.append(db_task)	
			db.add(db_task)   	
			db.commit()
			db.refresh(db_task)			
			return db_task
		else:
			raise HTTPException(status_code=500, detail="Task already exists in selected Labor")		
	except IntegrityError as e:
		raise HTTPException(status_code=500, detail="Integrity error")
	except SQLAlchemyError as e: 
		raise HTTPException(status_code=405, detail="Unexpected error when creating task")	
	
@app.get("/read_tasks/", status_code=status.HTTP_201_CREATED)  
async def read_tasks(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
				skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	db_tasks = db.query(
					models.Task.id,
					models.Task.description,
					models.Task.mechanicals,					
					models.Task.hour,
					models.Task.hour_men,
					models.Task.task_price,
					models.Task.inidate_task,
					models.Task.upddate_task,
					models.Task.enddate_task,
					models.Task.is_active,
					models.Labor.type,
					(models.Labor.id).label('labor_task'),
				).join(models.Task, models.Labor.id == models.Task.labor_task_id
				).all()	
	
	return db_tasks
	
@app.get("/read_tasks_by_labor_id/{labor_id}", status_code=status.HTTP_201_CREATED)  
async def read_tasks_by_labor_id(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
						labor_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	db_tasks = db.query(
					models.Task.id,
					models.Task.description,
					models.Task.mechanicals,
					models.Task.hour,					
					models.Task.inidate_task,
					models.Task.upddate_task,
					models.Task.enddate_task,
					models.Task.is_active,
					models.Task.hour_men,
					models.Task.task_price,
					models.Labor.type,
					(models.Labor.id).label('labor_task'),
				).join(models.Task, models.Labor.id == models.Task.labor_task_id
				).filter_by(labor_task_id = labor_id
				).all()	
	return db_tasks	
	
@app.put("/activate_task/{id}", status_code=status.HTTP_201_CREATED) 
async def activate_task(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
				id: str, task: schemas.TaskActive, db: Session = Depends(get_db)):
	db_task = db.query(models.Task).filter(models.Task.id == id).first()
	if db_task is None:
		raise HTTPException(status_code=404, detail="Task not found")
	db_task.is_active=task.is_active;		
	db.commit()
	db.refresh(db_task)	
	return {"Response": "Task successfully changed its status"}	
		
@app.put("/update_task/{id}", status_code=status.HTTP_201_CREATED) 
async def update_task(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
				id: str, upd: schemas.TaskUPD, db: Session = Depends(get_db)):
	db_task = db.query(models.Task).filter(models.Task.id == id).first()
	if db_task is None:
		raise HTTPException(status_code=404, detail="Task not found")
	db_task.mechanicals=upd.mechanicals
	db_task.hour=upd.hour
	db_task.task_price=upd.task_price
	db_task.hour_men=(upd.hour * upd.mechanicals)
	db.commit()
	db.refresh(db_task)	
	return db_task

@app.put("/update_labor_date/{task_id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
async def update_labor_date(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
						task_id: str, task: schemas.TaskUpdDate, db: Session = Depends(get_db)):
	db_task = db.query(models.Task).filter(models.Task.id == labor_id).first()
	if db_task is None:
		raise HTTPException(status_code=404, detail="Task not found")
	db_task.upddate_task = func.now()
	db_task.enddate_task = task.enddate_task
	db.commit()
	db.refresh(db_task)	
	return db_task	

@app.delete("/delete_task/{id}", status_code=status.HTTP_201_CREATED) 
async def delete_task(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
				id: str, db: Session = Depends(get_db)):
	db_task = db.query(models.Task).filter(models.Task.id == id).first()
	if db_task is None:
		raise HTTPException(status_code=404, detail="Task not found")	
	db.delete(db_task)	
	db.commit()
	return {"Deleted": "Delete Successfuly"}

#########################
#------EQUIPMENT--------- 
#########################
@app.post("/create_equipment/", status_code=status.HTTP_201_CREATED) 
async def create_equipment(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					equipment: schemas.Equipment, db: Session = Depends(get_db)):		
	try:	
		equipments_in_db = db.query(
							models.Equipment.id,
							models.Equipment.equipment_name,
							models.Labor.type,							
							(models.Labor.id).label('labor_parent')
							).join(models.Equipment, models.Labor.id == models.Equipment.labor_equipment_id
						).filter_by(equipment_name = equipment.equipment_name
						).filter_by(labor_equipment_id = equipment.labor_equipment_id
						).all()	
		if 	len(equipments_in_db) == 0:		
			db_equipment = models.Equipment(
				equipment_name=equipment.equipment_name,	
				equipment_quantity=equipment.equipment_quantity,
				equipment_unit_price=equipment.equipment_unit_price,  
				equipment_amount=(equipment.equipment_unit_price * equipment.equipment_quantity), 
				labor_equipment_id=equipment.labor_equipment_id,
			)			
			db_parent_labor = db.query(models.Labor).filter(models.Labor.id == equipment.labor_equipment_id).first()
			db_parent_labor.equipments.append(db_equipment)	
			db.add(db_equipment)   	
			db.commit()
			db.refresh(db_equipment)			
			return db_equipment
		else:
			raise HTTPException(status_code=500, detail="Equipment already exists in selected Labor")		
	except IntegrityError as e:
		raise HTTPException(status_code=500, detail="Integrity error")
	except SQLAlchemyError as e: 
		raise HTTPException(status_code=405, detail="Unexpected error when creating equipment")		

@app.get("/read_equipments/", status_code=status.HTTP_201_CREATED)  
async def read_equipments(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	db_equipments = db.query(
					models.Equipment.id,
					models.Equipment.equipment_name,
					models.Equipment.equipment_quantity,					
					models.Equipment.equipment_unit_price,
					models.Equipment.equipment_amount,
					models.Labor.type,
					(models.Labor.id).label('labor_equipment'),
				).join(models.Equipment, models.Labor.id == models.Equipment.labor_equipment_id
				).all()	
	
	return db_equipments
	
@app.get("/read_equipments_by_labor_id/{labor_id}", status_code=status.HTTP_201_CREATED)  
async def read_equipments_by_labor_id(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
							labor_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	db_equipments = db.query(
					models.Equipment.id,
					models.Equipment.equipment_name,
					models.Equipment.equipment_quantity,
					models.Equipment.equipment_unit_price,					
					models.Equipment.equipment_amount,
					models.Labor.type,
					(models.Labor.id).label('labor_equipment'),
				).join(models.Equipment, models.Labor.id == models.Equipment.labor_equipment_id
				).filter_by(labor_equipment_id = labor_id
				).all()	
	return db_equipments
	
@app.put("/update_equipment/{id}", status_code=status.HTTP_201_CREATED) 
async def update_equipment(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					id: str, upd: schemas.EquipmentUPD, db: Session = Depends(get_db)):
	db_equipment = db.query(models.Equipment).filter(models.Equipment.id == id).first()
	if db_equipment is None:
		raise HTTPException(status_code=404, detail="Task not found")
	db_equipment.equipment_quantity=upd.equipment_quantity
	db_equipment.equipment_unit_price=upd.equipment_unit_price
	db_equipment.equipment_amount=(upd.equipment_quantity * upd.equipment_unit_price)
	db.commit()
	db.refresh(db_equipment)	
	return db_equipment	

@app.delete("/delete_equipment/{id}", status_code=status.HTTP_201_CREATED) 
async def delete_equipment(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					id: str, db: Session = Depends(get_db)):
	db_equipment = db.query(models.Equipment).filter(models.Equipment.id == id).first()
	if db_equipment is None:
		raise HTTPException(status_code=404, detail="Task not found")	
	db.delete(db_equipment)	
	db.commit()
	return {"Deleted": "Delete Successfuly"}
	
#########################
#-------MATERIAL---------
#########################	

@app.post("/create_material/", status_code=status.HTTP_201_CREATED) 
async def create_material(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					material: schemas.Material, db: Session = Depends(get_db)):		
	try:	
		materials_in_db = db.query(
							models.Material.id,
							models.Material.material_name,
							models.Labor.type,							
							(models.Labor.id).label('labor_parent')
							).join(models.Material, models.Labor.id == models.Material.labor_material_id
						).filter_by(material_name = material.material_name
						).filter_by(labor_material_id = material.labor_material_id
						).all()	
		if 	len(materials_in_db) == 0:		
			db_material = models.Material(
				material_name=material.material_name,	
				material_type=material.material_type,
				material_quantity=material.material_quantity,
				material_price=material.material_price,  
				material_amount=(material.material_price * material.material_quantity), 
				labor_material_id=material.labor_material_id,
			)			
			db_parent_labor = db.query(models.Labor).filter(models.Labor.id == material.labor_material_id).first()
			db_parent_labor.materials.append(db_material)	
			db.add(db_material)   	
			db.commit()
			db.refresh(db_material)			
			return db_material
		else:
			raise HTTPException(status_code=500, detail="Material already exists in selected Labor")		
	except IntegrityError as e:
		raise HTTPException(status_code=500, detail="Integrity error")
	except SQLAlchemyError as e: 
		raise HTTPException(status_code=405, detail="Unexpected error when creating material")		

@app.get("/read_materials/", status_code=status.HTTP_201_CREATED)  
async def read_materials(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	db_materials = db.query(
					models.Material.id,
					models.Material.material_name,
					models.Material.material_type,
					models.Material.material_quantity,					
					models.Material.material_price,
					models.Material.material_amount,
					models.Labor.type,
					(models.Labor.id).label('labor_material'),
				).join(models.Material, models.Labor.id == models.Material.labor_material_id
				).all()	
	
	return db_materials
	
@app.get("/read_materials_by_labor_id/{labor_id}", status_code=status.HTTP_201_CREATED)  
async def read_materials_by_labor_id(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
						labor_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	db_materials = db.query(
					models.Material.id,
					models.Material.material_name,
					models.Material.material_type,
					models.Material.material_quantity,		
					models.Material.material_price,							
					models.Material.material_amount,
					models.Labor.type,
					(models.Labor.id).label('labor_material'),
				).join(models.Material, models.Labor.id == models.Material.labor_material_id
				).filter_by(labor_material_id = labor_id
				).all()	
	return db_materials
	
@app.put("/update_material/{id}", status_code=status.HTTP_201_CREATED) 
async def update_material(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					id: str, upd: schemas.MaterialUPD, db: Session = Depends(get_db)):
	db_material = db.query(models.Material).filter(models.Material.id == id).first()
	if db_material is None:
		raise HTTPException(status_code=404, detail="Material not found")
	db_material.material_quantity=upd.material_quantity
	db_material.material_price=upd.material_price
	db_material.material_amount=(upd.material_quantity * upd.material_price)
	db.commit()
	db.refresh(db_material)	
	return db_material

@app.delete("/delete_material/{id}", status_code=status.HTTP_201_CREATED) 
async def delete_material(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					id: str, db: Session = Depends(get_db)):
	db_material = db.query(models.Material).filter(models.Material.id == id).first()
	if db_material is None:
		raise HTTPException(status_code=404, detail="Material not found")	
	db.delete(db_material)	
	db.commit()
	return {"Response": "Delete Successfuly"}
	
##################################
###  STATISTICS FOR LABORS ID  ####
##################################

#------------Example queries TASK here----------

@app.get("/summary_amount_tasks_by_labor_id/{labor_id}", status_code=status.HTTP_201_CREATED)  
async def summary_amount_tasks_by_labor_id(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
							labor_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	db_project_summary = db.query(
					models.Labor.type,
					func.sum(models.Task.hour_men).label('hour_men'),
					func.sum(models.Task.task_price).label('task_price'),
					func.count(models.Task.id).label('task_number'),
				).join(models.Task, models.Labor.id == models.Task.labor_task_id
				).filter(models.Task.is_active == True
				).filter_by(labor_task_id = labor_id
				).all()	
	return db_project_summary

@app.get("/summary_tasks_by_project_id/{project_id}", status_code=status.HTTP_201_CREATED)  
async def summary_tasks_by_project_id(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
							project_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('task_number'),
		func.sum(models.Task.hour_men).label('hour_men'),
		func.sum(models.Task.task_price).label('task_amount'),
	).select_from(
		models.Task
	).filter(
		models.Task.is_active == True 
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	query = db.query(
		models.Labor.id,
		models.Labor.type,
		func.sum(sub_query.c.task_number).label('task_number'),
		func.sum(sub_query.c.hour_men).label('hour_men'),
		func.sum(sub_query.c.task_amount).label('task_amount'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	).filter(
		models.Labor.is_active == True 	
	).filter(
		models.Project.id == project_id 		
	).group_by(
		models.Labor.id		
	).all()
	
	return query

@app.get("/summary_all_tasks/", status_code=status.HTTP_201_CREATED)  
async def summary_all_tasks(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('task_number'),
		func.sum(models.Task.hour_men).label('hour_men'),
		func.sum(models.Task.task_price).label('task_price'),
	).select_from(
		models.Task
	).filter(
		models.Task.is_active == True 
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	query = db.query(
		models.Project.id,
		models.Project.project_name,
		func.count(models.Labor.id).label('labors_number'),
		func.sum(sub_query.c.task_number).label('task_number'),
		func.sum(sub_query.c.hour_men).label('hour_men'),
		func.sum(sub_query.c.task_price).label('task_price'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	).filter(
		models.Labor.is_active == True 	
	).group_by(
		models.Project.id		
	).all()
	
	return query
	
@app.get("/summary_all_tasks_labor_type/", status_code=status.HTTP_201_CREATED)  
async def summary_all_tasks_labor_type(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('task_number'),
		func.sum(models.Task.hour_men).label('hour_men'),
		func.sum(models.Task.task_price).label('task_price'),
	).select_from(
		models.Task
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	query = db.query(
		models.Labor.type,
		func.count(models.Labor.type).label('type_number'),
		func.sum(sub_query.c.task_number).label('task_number'),
		func.sum(sub_query.c.hour_men).label('hour_men'),
		func.sum(sub_query.c.task_price).label('task_price'),
	).select_from(
		models.Labor
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	).group_by(
		models.Labor.type		
	).all()
	
	return query
	
@app.get("/summary_tasks_total/", status_code=status.HTTP_201_CREATED)  
async def summary_tasks_total(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('task_number'),
		func.sum(models.Task.hour_men).label('hour_men'),
		func.sum(models.Task.task_price).label('task_price'),
	).select_from(
		models.Task
	).filter(
		models.Task.is_active == True 
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	query = db.query(
		func.count(models.Labor.id).label('labors_number'),
		func.sum(sub_query.c.task_number).label('task_number'),
		func.sum(sub_query.c.hour_men).label('hour_men'),
		func.sum(sub_query.c.task_price).label('task_price'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	).filter(
		models.Labor.is_active == True 	
	).all()
	
	return query
	
#------------Example queries EQUIPMENT here----------

@app.get("/summary_amount_equipments_by_labor_id/{labor_id}", status_code=status.HTTP_201_CREATED)  
async def summary_amount_equipments_by_labor_id(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
						labor_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	db_project_summary = db.query(
					models.Labor.type,
					func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
					func.count(models.Equipment.id).label('equipment_number'),
				).join(models.Equipment, models.Labor.id == models.Equipment.labor_equipment_id
				).filter_by(labor_equipment_id = labor_id
				).all()	
	return db_project_summary

@app.get("/summary_equipments_by_project_id/{project_id}", status_code=status.HTTP_201_CREATED)  
async def summary_equipments_by_project_id(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
							project_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Equipment.labor_equipment_id.label('labor_id'),		
		func.count(models.Equipment.id).label('equipment_number'),
		func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
	).select_from(
		models.Equipment
	).group_by(
		models.Equipment.labor_equipment_id
	).subquery()
	
	query = db.query(
		models.Labor.id,
		models.Labor.type,
		func.sum(sub_query.c.equipment_number).label('equipment_number'),
		func.sum(sub_query.c.equipment_amount).label('equipment_amount'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	).filter(
		models.Labor.is_active == True 	
	).filter(
		models.Project.id == project_id 		
	).group_by(
		models.Labor.id		
	).all()
	
	return query

@app.get("/summary_all_equipments/", status_code=status.HTTP_201_CREATED)  
async def summary_all_equipments(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Equipment.labor_equipment_id.label('labor_id'),		
		func.count(models.Equipment.id).label('equipment_number'),
		func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
	).select_from(
		models.Equipment
	).group_by(
		models.Equipment.labor_equipment_id
	).subquery()
	
	query = db.query(
		models.Project.id,
		models.Project.project_name,
		func.count(models.Labor.id).label('labors_number'),
		func.sum(sub_query.c.equipment_number).label('equipment_number'),
		func.sum(sub_query.c.equipment_amount).label('equipment_amount'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	).filter(
		models.Labor.is_active == True 	
	).group_by(
		models.Project.id		
	).all()
	
	return query
	
@app.get("/summary_equipments_total/", status_code=status.HTTP_201_CREATED)  
async def summary_equipments_total(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Equipment.labor_equipment_id.label('labor_id'),		
		func.count(models.Equipment.id).label('equipment_number'),
		func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
	).select_from(
		models.Equipment
	).group_by(
		models.Equipment.labor_equipment_id
	).subquery()
	
	query = db.query(
		func.count(models.Labor.id).label('labors_number'),
		func.sum(sub_query.c.equipment_number).label('equipment_number'),
		func.sum(sub_query.c.equipment_amount).label('equipment_amount'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	).filter(
		models.Labor.is_active == True 	
	).all()
	
	return query
	
#------------Example queries MATERIAL here----------

@app.get("/summary_amount_materials_by_labor_id/{labor_id}", status_code=status.HTTP_201_CREATED)  
async def summary_amount_materials_by_labor_id(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					labor_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	db_project_summary = db.query(
					models.Labor.type,
					models.Material.material_type,
					func.sum(models.Material.material_amount).label('material_amount'),
					func.count(models.Material.id).label('material_number'),
					func.count(models.Material.material_type).label('material_type_number'),
				).join(models.Material, models.Labor.id == models.Material.labor_material_id
				).filter_by(labor_material_id = labor_id
				).group_by(models.Material.material_type				
				).all()	
	return db_project_summary

@app.get("/summary_materials_by_project_id/{project_id}", status_code=status.HTTP_201_CREATED)  
async def summary_materials_by_project_id(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					project_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Material.labor_material_id.label('labor_id'),
		models.Material.material_type.label('material_type'),
		func.count(models.Material.id).label('material_number'),
		func.sum(models.Material.material_amount).label('material_amount'),
	).select_from(
		models.Material
	).group_by(
		models.Material.labor_material_id, models.Material.material_type
	).subquery()
	
	query = db.query(
		models.Labor.id,
		models.Labor.type,
		sub_query.c.material_type.label('material_type'),
		func.sum(sub_query.c.material_number).label('material_number'),
		func.sum(sub_query.c.material_amount).label('material_amount'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	).filter(
		models.Labor.is_active == True 	
	).filter(
		models.Project.id == project_id 		
	).group_by(
		models.Labor.id, sub_query.c.material_type.label('material_type')
	).all()
	
	return query

@app.get("/summary_all_materials/", status_code=status.HTTP_201_CREATED)  
async def summary_all_materials(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Material.labor_material_id.label('labor_id'),		
		models.Material.material_type.label('material_type'),
		func.count(models.Material.id).label('material_number'),
		func.sum(models.Material.material_amount).label('material_amount'),
	).select_from(
		models.Material
	).group_by(
		models.Material.labor_material_id
	).subquery()
	
	query = db.query(
		models.Project.id,
		models.Project.project_name,
		func.count(models.Labor.id).label('labors_number'),
		func.sum(sub_query.c.material_number).label('material_number'),
		func.sum(sub_query.c.material_amount).label('material_amount'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	).filter(
		models.Labor.is_active == True 	
	).group_by(
		models.Project.id, models.Labor.id	
	).all()
	
	return query
	
@app.get("/summary_materials_total/", status_code=status.HTTP_201_CREATED)  
async def summary_materials_total(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Material.labor_material_id.label('labor_id'),		
		func.count(models.Material.id).label('material_number'),
		func.sum(models.Material.material_amount).label('material_amount'),
	).select_from(
		models.Material
	).group_by(
		models.Material.labor_material_id
	).subquery()
	
	query = db.query(
		func.count(models.Labor.id).label('labors_number'),
		func.sum(sub_query.c.material_number).label('material_number'),
		func.sum(sub_query.c.material_amount).label('material_amount'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	).all()
	
	return query

#-------------PER ITEM--------------------------------------

#para todas las labores en general calcula el número de tareas, equipos y materiales

@app.get("/summary_all_item_labor_type/", status_code=status.HTTP_201_CREATED)  
async def summary_all_item_labor_type(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):

	sub_task = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('task_number'),
		func.sum(models.Task.hour_men).label('hour_men'),
		func.sum(models.Task.task_price).label('task_price'),
	).filter(
		models.Task.is_active == True
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	sub_equipment = db.query(
		models.Equipment.labor_equipment_id.label('labor_id'),		
		func.count(models.Equipment.id).label('equipment_number'),
		func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
	).group_by(
		models.Equipment.labor_equipment_id
	).subquery()
	
	sub_material = db.query(
		models.Material.labor_material_id.label('labor_id'),		
		func.count(models.Material.id).label('material_number'),
		func.sum(models.Material.material_amount).label('material_amount'),
	).group_by(
		models.Material.labor_material_id
	).subquery()
	
	query = db.query(
		models.Labor.type,
		func.count(models.Labor.type).label('type_number'),		
		func.sum(case([(sub_task.c.task_number == None, 0)], else_= sub_task.c.task_number)).label('task_number'),
		func.sum(case([(sub_task.c.hour_men == None, 0)], else_= sub_task.c.hour_men)).label('hour_men'),
		func.sum(case([(sub_task.c.task_price == None, 0)], else_= sub_task.c.task_price)).label('task_price'),
		func.sum(case([(sub_equipment.c.equipment_number == None, 0)], else_= sub_equipment.c.equipment_number)).label('equipment_number'),
		func.sum(case([(sub_equipment.c.equipment_amount == None, 0)], else_= sub_equipment.c.equipment_amount)).label('equipment_amount'),
		func.sum(case([(sub_material.c.material_number == None, 0)], else_= sub_material.c.material_number)).label('material_number'),
		func.sum(case([(sub_material.c.material_amount == None, 0)], else_= sub_material.c.material_amount)).label('material_amount'),
	).outerjoin(
		sub_equipment, models.Labor.id == sub_equipment.c.labor_id
	).outerjoin(
		sub_task, models.Labor.id == sub_task.c.labor_id
	).outerjoin(
		sub_material, models.Labor.id == sub_material.c.labor_id
	).filter(
		models.Labor.is_active == True
	).group_by(
		models.Labor.type		
	).all()
	
	return query

#para una labor calcula el número de tareas, equipos y materiales
#y agrega el total acumulado

@app.get("/summary_amount_labor_id/{labor_id}", status_code=status.HTTP_201_CREATED)  
async def summary_amount_labor_id(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					labor_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_task = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('task_number'),
		func.sum(models.Task.hour_men).label('hour_men'),
		func.sum(models.Task.task_price).label('task_price'),
	).filter(
		models.Task.is_active == True
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	sub_equipment = db.query(
		models.Equipment.labor_equipment_id.label('labor_id'),		
		func.count(models.Equipment.id).label('equipment_number'),
		func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
	).group_by(
		models.Equipment.labor_equipment_id
	).subquery()
	
	sub_material = db.query(
		models.Material.labor_material_id.label('labor_id'),		
		func.count(models.Material.id).label('material_number'),
		func.sum(models.Material.material_amount).label('material_amount'),
	).group_by(
		models.Material.labor_material_id
	).subquery()
	
	query = db.query(
		models.Labor.type,
		models.Labor.id,
		func.sum(case([(sub_task.c.task_number == None, 0)], else_= sub_task.c.task_number)).label('task_number'),
		func.sum(case([(sub_task.c.hour_men == None, 0)], else_= sub_task.c.hour_men)).label('hour_men'),
		func.sum(case([(sub_task.c.task_price == None, 0)], else_= sub_task.c.task_price)).label('task_price'),
		func.sum(case([(sub_equipment.c.equipment_number == None, 0)], else_= sub_equipment.c.equipment_number)).label('equipment_number'),
		func.sum(case([(sub_equipment.c.equipment_amount == None, 0)], else_= sub_equipment.c.equipment_amount)).label('equipment_amount'),
		func.sum(case([(sub_material.c.material_number == None, 0)], else_= sub_material.c.material_number)).label('material_number'),
		func.sum(case([(sub_material.c.material_amount == None, 0)], else_= sub_material.c.material_amount)).label('material_amount'),
		func.sum(
			case([(sub_task.c.task_price == None, 0)], else_= sub_task.c.task_price) +
			case([(sub_equipment.c.equipment_amount == None, 0)], else_= sub_equipment.c.equipment_amount) +
			case([(sub_material.c.material_amount == None, 0)], else_= sub_material.c.material_amount)
		).label('Total_amount')
	).outerjoin(
		sub_equipment, models.Labor.id == sub_equipment.c.labor_id
	).outerjoin(
		sub_task, models.Labor.id == sub_task.c.labor_id
	).outerjoin(
		sub_material, models.Labor.id == sub_material.c.labor_id
	).filter(
		models.Labor.id == labor_id 		
	).all()
	
	return query

#para todas las labores en general calcula el número de tareas, equipos y materiales
#y agrega el total acumulado

@app.get("/summary_amount_labor_type/", status_code=status.HTTP_201_CREATED)  
async def summary_amount_labor_type(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_task = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('task_number'),
		func.sum(models.Task.hour_men).label('hour_men'),
		func.sum(models.Task.task_price).label('task_price'),
	).filter(
		models.Task.is_active == True
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	sub_equipment = db.query(
		models.Equipment.labor_equipment_id.label('labor_id'),		
		func.count(models.Equipment.id).label('equipment_number'),
		func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
	).group_by(
		models.Equipment.labor_equipment_id
	).subquery()
	
	sub_material = db.query(
		models.Material.labor_material_id.label('labor_id'),		
		func.count(models.Material.id).label('material_number'),
		func.sum(models.Material.material_amount).label('material_amount'),
	).group_by(
		models.Material.labor_material_id
	).subquery()
	
	query = db.query(
		models.Labor.type,
		func.count(models.Labor.type).label('type_number'),		
		func.sum(case([(sub_task.c.task_number == None, 0)], else_= sub_task.c.task_number)).label('task_number'),
		func.sum(case([(sub_task.c.hour_men == None, 0)], else_= sub_task.c.hour_men)).label('hour_men'),
		func.sum(case([(sub_task.c.task_price == None, 0)], else_= sub_task.c.task_price)).label('task_price'),
		func.sum(case([(sub_equipment.c.equipment_number == None, 0)], else_= sub_equipment.c.equipment_number)).label('equipment_number'),
		func.sum(case([(sub_equipment.c.equipment_amount == None, 0)], else_= sub_equipment.c.equipment_amount)).label('equipment_amount'),
		func.sum(case([(sub_material.c.material_number == None, 0)], else_= sub_material.c.material_number)).label('material_number'),
		func.sum(case([(sub_material.c.material_amount == None, 0)], else_= sub_material.c.material_amount)).label('material_amount'),
		func.sum(
			case([(sub_task.c.task_price == None, 0)], else_= sub_task.c.task_price) +
			case([(sub_equipment.c.equipment_amount == None, 0)], else_= sub_equipment.c.equipment_amount) +
			case([(sub_material.c.material_amount == None, 0)], else_= sub_material.c.material_amount)
		).label('Total_amount')
	).outerjoin(
		sub_equipment, models.Labor.id == sub_equipment.c.labor_id
	).outerjoin(
		sub_task, models.Labor.id == sub_task.c.labor_id
	).outerjoin(
		sub_material, models.Labor.id == sub_material.c.labor_id
	).filter(
		models.Labor.is_active == True
	).group_by(
		models.Labor.type		
	).all()
	
	return query

#para un projecto (project_id) calcula el número de tareas, equipos y materiales
#y agrupa por tipo de labor

@app.get("/stats_amount_by_project/{project_id}", status_code=status.HTTP_201_CREATED)  
async def stats_amount_by_project(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					project_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_task = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('task_number'),
		func.sum(models.Task.hour_men).label('hour_men'),
		func.sum(models.Task.task_price).label('task_price'),
	).filter(
		models.Task.is_active == True
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	sub_equipment = db.query(
		models.Equipment.labor_equipment_id.label('labor_id'),		
		func.count(models.Equipment.id).label('equipment_number'),
		func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
	).group_by(
		models.Equipment.labor_equipment_id
	).subquery()
	
	sub_material = db.query(
		models.Material.labor_material_id.label('labor_id'),
		models.Material.material_type.label('material_type'),
		func.count(models.Material.id).label('material_number'),
		func.sum(models.Material.material_amount).label('material_amount'),
	).group_by(
		models.Material.labor_material_id, models.Material.material_type
	).subquery()
	
	query = db.query(
		models.Project.project_name,
		models.Project.id,
		(models.Labor.id).label('labor_id'),
		models.Labor.type,
		func.count(case([(sub_task.c.task_number == None, 0)], else_= sub_task.c.task_number)).label('task_number'),
		func.sum(case([(sub_task.c.hour_men == None, 0)], else_= sub_task.c.hour_men)).label('hour_men'),
		func.sum(case([(sub_task.c.task_price == None, 0)], else_= sub_task.c.task_price)).label('task_price'),
		func.sum(case([(sub_equipment.c.equipment_number == None, 0)], else_= sub_equipment.c.equipment_number)).label('equipment_number'),
		func.sum(case([(sub_equipment.c.equipment_amount == None, 0)], else_= sub_equipment.c.equipment_amount)).label('equipment_amount'),
		func.sum(case([(sub_material.c.material_number == None, 0)], else_= sub_material.c.material_number)).label('material_number'),
		func.sum(case([(sub_material.c.material_amount == None, 0)], else_= sub_material.c.material_amount)).label('material_amount'),
		func.sum(
			case([(sub_task.c.task_price == None, 0)], else_= sub_task.c.task_price) +
			case([(sub_equipment.c.equipment_amount == None, 0)], else_= sub_equipment.c.equipment_amount) +
			case([(sub_material.c.material_amount == None, 0)], else_= sub_material.c.material_amount)
		).label('Total_amount')
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).outerjoin(
		sub_equipment, models.Labor.id == sub_equipment.c.labor_id
	).outerjoin(
		sub_task, models.Labor.id == sub_task.c.labor_id
	).outerjoin(
		sub_material, models.Labor.id == sub_material.c.labor_id
	).filter(
		models.Labor.is_active == True
	).filter(
		models.Project.id == project_id 		
	).order_by(
		models.Labor.type		
	).group_by(
		models.Labor.id		
	).all()
	
	return query
	
@app.get("/stats_amount_for_all_project/", status_code=status.HTTP_201_CREATED)  
async def stats_amount_for_all_project(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_task = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('task_number'),
		func.sum(models.Task.hour_men).label('hour_men'),
		func.sum(models.Task.task_price).label('task_price'),
	).filter(
		models.Task.is_active == True
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	sub_equipment = db.query(
		models.Equipment.labor_equipment_id.label('labor_id'),		
		func.count(models.Equipment.id).label('equipment_number'),
		func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
	).group_by(
		models.Equipment.labor_equipment_id
	).subquery()
	
	sub_material = db.query(
		models.Material.labor_material_id.label('labor_id'),
		models.Material.material_type.label('material_type'),
		func.count(models.Material.id).label('material_number'),
		func.sum(models.Material.material_amount).label('material_amount'),
	).group_by(
		models.Material.labor_material_id, models.Material.material_type
	).subquery()
	
	query = db.query(
		models.Project.project_name,
		models.Project.id,
		(models.Labor.id).label('labor_id'),
		models.Labor.type,
		func.count(case([(sub_task.c.task_number == None, 0)], else_= sub_task.c.task_number)).label('task_number'),
		func.sum(case([(sub_task.c.hour_men == None, 0)], else_= sub_task.c.hour_men)).label('hour_men'),
		func.sum(case([(sub_task.c.task_price == None, 0)], else_= sub_task.c.task_price)).label('task_price'),
		func.sum(case([(sub_equipment.c.equipment_number == None, 0)], else_= sub_equipment.c.equipment_number)).label('equipment_number'),
		func.sum(case([(sub_equipment.c.equipment_amount == None, 0)], else_= sub_equipment.c.equipment_amount)).label('equipment_amount'),
		func.sum(case([(sub_material.c.material_number == None, 0)], else_= sub_material.c.material_number)).label('material_number'),
		func.sum(case([(sub_material.c.material_amount == None, 0)], else_= sub_material.c.material_amount)).label('material_amount'),
		func.sum(
			case([(sub_task.c.task_price == None, 0)], else_= sub_task.c.task_price) +
			case([(sub_equipment.c.equipment_amount == None, 0)], else_= sub_equipment.c.equipment_amount) +
			case([(sub_material.c.material_amount == None, 0)], else_= sub_material.c.material_amount)
		).label('Total_amount')
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).outerjoin(
		sub_equipment, models.Labor.id == sub_equipment.c.labor_id
	).outerjoin(
		sub_task, models.Labor.id == sub_task.c.labor_id
	).outerjoin(
		sub_material, models.Labor.id == sub_material.c.labor_id
	).filter(
		models.Labor.is_active == True
	).order_by(
		models.Project.project_name, models.Labor.type
	).group_by(
		models.Project.id, models.Labor.id		
	).all()
	
	return query

@app.get("/total_amount_for_projects/", status_code=status.HTTP_201_CREATED)  
async def total_amount_for_projects(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_task = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('task_number'),
		func.sum(models.Task.hour_men).label('hour_men'),
		func.sum(models.Task.task_price).label('task_price'),
	).filter(
		models.Task.is_active == True
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	sub_equipment = db.query(
		models.Equipment.labor_equipment_id.label('labor_id'),		
		func.count(models.Equipment.id).label('equipment_number'),
		func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
	).group_by(
		models.Equipment.labor_equipment_id
	).subquery()
	
	sub_material = db.query(
		models.Material.labor_material_id.label('labor_id'),
		models.Material.material_type.label('material_type'),
		func.count(models.Material.id).label('material_number'),
		func.sum(models.Material.material_amount).label('material_amount'),
	).group_by(
		models.Material.labor_material_id, models.Material.material_type
	).subquery()
	
	db_project_total = db.query(
		func.count(case([(sub_task.c.task_number == None, 0)], else_= sub_task.c.task_number)).label('task_number'),
		func.sum(case([(sub_task.c.hour_men == None, 0)], else_= sub_task.c.hour_men)).label('hour_men'),
		func.sum(case([(sub_task.c.task_price == None, 0)], else_= sub_task.c.task_price)).label('task_price'),
		func.sum(case([(sub_equipment.c.equipment_number == None, 0)], else_= sub_equipment.c.equipment_number)).label('equipment_number'),
		func.sum(case([(sub_equipment.c.equipment_amount == None, 0)], else_= sub_equipment.c.equipment_amount)).label('equipment_amount'),
		func.sum(case([(sub_material.c.material_number == None, 0)], else_= sub_material.c.material_number)).label('material_number'),
		func.sum(case([(sub_material.c.material_amount == None, 0)], else_= sub_material.c.material_amount)).label('material_amount'),
		func.sum(
			case([(sub_task.c.task_price == None, 0)], else_= sub_task.c.task_price) +
			case([(sub_equipment.c.equipment_amount == None, 0)], else_= sub_equipment.c.equipment_amount) +
			case([(sub_material.c.material_amount == None, 0)], else_= sub_material.c.material_amount)
		).label('Total_amount')
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).outerjoin(
		sub_equipment, models.Labor.id == sub_equipment.c.labor_id
	).outerjoin(
		sub_task, models.Labor.id == sub_task.c.labor_id
	).outerjoin(
		sub_material, models.Labor.id == sub_material.c.labor_id
	).filter(
		models.Labor.is_active == True
	).all()
	
	return db_project_total
	
#----------------------------------------------------------
#   Hasta aqui todo bien
#--------------------ACTIVE TASK- BY PROJECTS--------------

@app.get("/summary_task_active_status_by_project/", status_code=status.HTTP_201_CREATED)  
async def summary_task_active_status_by_project(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query_active = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('number_active'),
	).select_from(
		models.Task
	).filter(
		models.Task.is_active == True 
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	sub_query_total = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('total_number'),
	).select_from(
		models.Task
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	query = db.query(
		models.Project.id,
		models.Project.project_name,
		models.Labor.type,
		models.Labor.id.label('labor_id'),
		sub_query_total.c.total_number.label('total_number'),
		sub_query_active.c.number_active.label('number_active'),
		(sub_query_total.c.total_number - sub_query_active.c.number_active).label('diff_active'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query_active, sub_query_active.c.labor_id == models.Labor.id
	).join(
		sub_query_total, sub_query_total.c.labor_id == models.Labor.id
	).filter(
		models.Labor.is_active == True
	).group_by(
		models.Project.id, models.Labor.id	
	).all()
	
	return query
	
@app.get("/summary_task_active_status_by_project_id/{project_id}", status_code=status.HTTP_201_CREATED)  
async def summary_task_active_status_by_project_id(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
						project_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query_active = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('number_active'),
	).select_from(
		models.Task
	).filter(
		models.Task.is_active == True 
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	sub_query_total = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('total_number'),
	).select_from(
		models.Task
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	query = db.query(
		models.Project.id,
		models.Project.project_name,
		models.Labor.type,
		models.Labor.id.label('labor_id'),
		sub_query_total.c.total_number.label('total_number'),
		sub_query_active.c.number_active.label('number_active'),
		(sub_query_total.c.total_number - sub_query_active.c.number_active).label('diff_active'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query_active, sub_query_active.c.labor_id == models.Labor.id
	).join(
		sub_query_total, sub_query_total.c.labor_id == models.Labor.id
	).filter(
		models.Labor.is_active == True
	).filter(
		models.Project.id == project_id 		
	).group_by(
		models.Project.id, models.Labor.id	
	).all()
	
	return query

#-------------General---per AMOUNT---------------
@app.get("/read_summary_labor_amount_by_id/{labor_id}", status_code=status.HTTP_201_CREATED)  
async def read_summary_labor_amount_by_id(#current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
							labor_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	db_summary = db.query(
					models.Labor.id,
					models.Labor.type,
					models.Labor.desc_labor,
					models.Labor.inidate_labor,
					models.Labor.enddate_labor,
					models.Labor.is_active,
					models.Project.project_name,
					(models.Project.id).label('project_labor'),				
					func.sum(models.Task.task_price + models.Equipment.equipment_amount + models.Material.material_amount).label('total_amount'),
				).join(models.Labor, models.Project.id == models.Labor.project_id
				).join(models.Task, models.Labor.id == models.Task.labor_task_id
				).join(models.Equipment, models.Labor.id == models.Equipment.labor_equipment_id
				).join(models.Material, models.Labor.id == models.Material.labor_material_id
				).filter(models.Labor.is_active == True
				).where(models.Labor.id == labor_id
				).all()	
				
	return db_summary
	
@app.get("/read_labors_summary_amount/", status_code=status.HTTP_201_CREATED)  
async def read_labors_summary_amount(#current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
							skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	db_summary = db.query(
					models.Labor.id,
					models.Labor.type,
					models.Labor.desc_labor,
					models.Labor.inidate_labor,
					models.Labor.enddate_labor,
					models.Labor.is_active,
					models.Project.project_name,
					(models.Project.id).label('project_labor'),				
					func.sum(models.Task.task_price + models.Equipment.equipment_amount + models.Material.material_amount).label('total_amount'),
				).join(models.Labor, models.Project.id == models.Labor.project_id
				).join(models.Task, models.Labor.id == models.Task.labor_task_id
				).join(models.Equipment, models.Labor.id == models.Equipment.labor_equipment_id
				).join(models.Material, models.Labor.id == models.Material.labor_material_id
				).filter(models.Task.is_active == True	
				).group_by(models.Labor.id
				).all()	
	return db_summary
	
@app.get("/read_summary_project_amount_by_id/{project_id}", status_code=status.HTTP_201_CREATED)  
async def read_summary_project_amount_by_id(#current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
							project_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	db_task = db.query(
		(models.Labor.id).label('labor_id'),	
		(models.Labor.project_id).label('labor_task_id'),
		func.sum(models.Task.task_price).label('task_amount'),
	).join(models.Labor, models.Labor.id == models.Task.labor_task_id
	).filter(models.Task.is_active == True
	).group_by(models.Labor.id
	).subquery()	#subquery()
	
	db_equipment = db.query(
		(models.Labor.id).label('labor_id'),	
		(models.Labor.project_id).label('labor_equipment_id'),	
		func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
	).join(models.Labor, models.Labor.id == models.Equipment.labor_equipment_id
	).group_by(models.Labor.id
	).subquery()	
	
	db_material = db.query(
		(models.Labor.id).label('labor_id'),	
		(models.Labor.project_id).label('labor_material_id'),	
		func.sum(models.Material.material_amount).label('material_amount'),
	).join(models.Labor, models.Labor.id == models.Material.labor_material_id
	).filter(models.Task.is_active == True
	).group_by(models.Labor.id
	).subquery()	

	db_labor = db.query(
		models.Project.project_name,
		models.Project.id,
		func.sum(db_task.c.task_amount).label('task_amount'),
		func.sum(db_equipment.c.equipment_amount).label('equipment_amount'),
	).select_from(models.Project
	).filter(db_task.c.labor_task_id == project_id
	).filter(db_equipment.c.labor_equipment_id == project_id
	).all()	
	
	return db_labor
	
@app.get("/read_projects_summary_amount/", status_code=status.HTTP_201_CREATED)  
async def read_projects_summary_amount(#current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
							skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	sub_query = db.query(
		(models.Labor.id).label('labor_id'),
		(models.Labor.project_id).label('project_id'),
		func.count(models.Labor.id).label('number_labors'),
		func.sum(models.Task.task_price + models.Equipment.equipment_amount + models.Material.material_amount).label('total_amount'),
	).select_from(
		models.Labor
	).join(
		models.Task, models.Labor.id == models.Task.labor_task_id
	).join(
		models.Equipment, models.Labor.id == models.Equipment.labor_equipment_id
	).join(
		models.Material, models.Labor.id == models.Material.labor_material_id
	).filter(
		models.Labor.is_active == True, models.Task.is_active == True
	).group_by(
		models.Labor.id
	).subquery()
	
	db_summary = db.query(					
		models.Project.project_name,
		(models.Project.id).label('project_labor'),
		func.sum(sub_query.c.number_labors).label('number_labors'),
		func.sum(sub_query.c.total_amount).label('total_amount'),
		sub_query.c.project_id
	).join(
		sub_query, models.Project.id == sub_query.c.project_id
	).group_by(
		models.Project.id
	).all()	
	
	return db_summary


#--------------TOP PROJECTS------------	

@app.get("/project_materials_top/", status_code=status.HTTP_201_CREATED)  
async def project_materials_top(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Material.labor_material_id.label('labor_id'),		
		func.count(models.Material.id).label('material_number'),
		func.sum(models.Material.material_amount).label('material_amount'),
	).select_from(
		models.Material
	).group_by(
		models.Material.labor_material_id
	).subquery()
	
	query = db.query(
		models.Project.id,
		models.Project.project_name,
		func.sum(sub_query.c.material_number).label('material_number'),
		func.sum(sub_query.c.material_amount).label('material_amount'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	).group_by(
		models.Project.id	
	).order_by(
		sub_query.c.material_amount.desc()
	).first()	
	
	return query
	
@app.get("/project_tasks_top/", status_code=status.HTTP_201_CREATED)  
async def project_tasks_top(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
				skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('task_number'),
		func.sum(models.Task.task_price).label('task_amount'),
	).select_from(
		models.Task
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	query = db.query(
		models.Project.id,
		models.Project.project_name,
		func.sum(sub_query.c.task_number).label('task_number'),
		func.sum(sub_query.c.task_amount).label('task_amount'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	).group_by(
		models.Project.id	
	).order_by(
		sub_query.c.task_amount.desc()
	).first()	
	
	return query
	
@app.get("/project_equipments_top/", status_code=status.HTTP_201_CREATED)  
async def project_equipments_top(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
						skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query = db.query(
		models.Equipment.labor_equipment_id.label('labor_id'),		
		func.count(models.Equipment.id).label('equipment_number'),
		func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
	).select_from(
		models.Equipment
	).group_by(
		models.Equipment.labor_equipment_id
	).subquery()
	
	query = db.query(
		models.Project.id,
		models.Project.project_name,
		func.sum(sub_query.c.equipment_number).label('equipment_number'),
		func.sum(sub_query.c.equipment_amount).label('equipment_amount'),
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query, sub_query.c.labor_id == models.Labor.id
	).group_by(
		models.Project.id	
	).order_by(
		sub_query.c.equipment_amount.desc()
	).first()	
	
	return query
	
@app.get("/summary_all_project_items_task/", status_code=status.HTTP_201_CREATED)  
async def summary_all_project_items_task(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
						skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	sub_query_task = db.query(
		models.Task.labor_task_id.label('labor_id'),
		func.count(models.Task.id).label('task_number'),
		func.sum(models.Task.hour_men).label('task_hour_men'),
		func.sum(models.Task.task_price).label('task_amount'),
	).select_from(
		models.Task
	).filter(
		models.Task.is_active == True
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	sub_query_labor = db.query(
		models.Labor.id,
		models.Labor.type,
		func.sum(sub_query_task.c.task_number).label('task_number'),
		func.sum(sub_query_task.c.task_hour_men).label('task_hour_men'),
		func.sum(sub_query_task.c.task_amount).label('task_amount'),
	).select_from(
		models.Labor
	).join(
		sub_query_task, sub_query_task.c.labor_id == models.Labor.id
	).filter(
		models.Labor.is_active == True
	).group_by(
		models.Labor.type	
	).subquery()
	
	query = db.query(
		models.Project.id,
		models.Project.project_name,
		func.count(models.Labor.type).label('labor_number'),
		sub_query_labor
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_query_labor, sub_query_labor.c.id == models.Labor.id
	).group_by(
		models.Project.id	
	).all()	
	
	return query
	
@app.get("/summary_all_project_items_equipments/", status_code=status.HTTP_201_CREATED)  
async def summary_all_project_items_equipments(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	#Equipments
	sub_query_equipment = db.query(
		models.Equipment.labor_equipment_id.label('labor_equipment_id'),
		func.count(models.Equipment.id).label('equipment_number'),
		func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
	).select_from(
		models.Equipment
	).group_by(
		models.Equipment.labor_equipment_id
	).subquery()
	
	sub_labor_equipment = db.query(
		models.Labor.id,
		models.Labor.type,
		func.sum(sub_query_equipment.c.equipment_number).label('equipment_number'),
		func.sum(sub_query_equipment.c.equipment_amount).label('equipment_amount'),		
	).select_from(
		models.Labor
	).join(
		sub_query_equipment, sub_query_equipment.c.labor_equipment_id == models.Labor.id
	).filter(
		models.Labor.is_active == True
	).group_by(
		models.Labor.type	
	).subquery()
	
	#Final
	query = db.query(
		models.Project.id,
		models.Project.project_name,
		func.count(models.Labor.type).label('labor_number'),
		sub_labor_equipment,
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_labor_equipment, sub_labor_equipment.c.id == models.Labor.id
	).group_by(
		models.Project.id	
	).all()	
	
	return query
	
@app.get("/summary_all_project_items_materials/", status_code=status.HTTP_201_CREATED)  
async def summary_all_project_items_materials(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	#Material
	sub_query_material = db.query(
		models.Material.labor_material_id.label('labor_material_id'),		
		func.count(models.Material.id).label('material_number'),
		func.sum(models.Material.material_amount).label('material_amount'),
	).select_from(
		models.Material
	).group_by(
		models.Material.labor_material_id
	).subquery()
	
	sub_labor_material = db.query(
		models.Labor.id,
		models.Labor.type,
		func.sum(sub_query_material.c.material_number).label('material_number'),
		func.sum(sub_query_material.c.material_amount).label('material_amount'),		
	).select_from(
		models.Labor
	).join(
		sub_query_material, sub_query_material.c.labor_material_id == models.Labor.id
	).filter(
		models.Labor.is_active == True
	).group_by(
		models.Labor.type	
	).subquery()
	
	#Final
	query = db.query(
		models.Project.id,
		models.Project.project_name,
		func.count(models.Labor.type).label('labor_number'),
		sub_labor_material,
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).join(
		sub_labor_material, sub_labor_material.c.id == models.Labor.id
	).group_by(
		models.Project.id	
	).all()	
	
	return query
	
@app.get("/number_projects_by_user/{email}", status_code=status.HTTP_201_CREATED)  
async def number_projects_by_user(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					email: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	query = db.query(
		func.count(models.Project.id).label('project_number'),
	).select_from(
		models.Project
	).filter(
		models.Project.mail_manager == email
	).first()	
	
	return query

#----------PDF CREATION-------------------	
def formar_query(query):

	data = []
	for row in query:
		temp_row = []
		for item in row:
			temp_row.append(str(item))
		data.append(temp_row)

	return data
	
def formar_query_totals(query):

	data = []
	for row in query:
		for item in row:
			data.append(str(item))

	return data
	
def formar_query_dict(query):

	data = []
	for item in query:		
		data.append(str(item))
	return data

def report_equipments_by_labor_id(labor_id: str, db: Session):

	db_project_labor = db.query(
		models.Project.project_name,
		models.Project.desc_proj,
		models.Project.enddate_proj,
		models.Project.manager,
		models.Labor.type
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).filter(
		models.Labor.id == labor_id
	).first()
	
	db_all_equipments = db.query(
		models.Equipment.equipment_name,
		models.Equipment.equipment_quantity,
		models.Equipment.equipment_unit_price,					
		models.Equipment.equipment_amount,
	).select_from(
		models.Equipment
	).filter_by(
		labor_equipment_id = labor_id		
	).all()
	
	db_equipment_total = db.query(
		func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
	).select_from(
		models.Labor
	).join(
		models.Equipment, models.Labor.id == models.Equipment.labor_equipment_id
	).filter(
		models.Labor.id == labor_id
	).all()	
	
	properties = formar_query_dict(db_project_labor)
	data_equipments = formar_query(db_all_equipments)
	total_equipment = formar_query_totals(db_equipment_total)	
	
	#Create table
	pdf = PDFTable()		
	#Setup page style
	pdf.alias_nb_pages()
	#Setup configuration
	#HEADER
	#Add image
	pdf.image('./logo.png', x=10, y=8, w=10)
	# Top margin: move 85 down
	pdf.ln(15) 			 
	pdf.cell(0, 5, f'Project name: {properties[0]}', 'L', ln=1)
	pdf.cell(0, 5, f'Work description: {properties[1]}', 'L', ln=1)
	pdf.cell(0, 5, f'End date: {properties[2]}', 'L', ln=1)
	pdf.cell(0, 5, f'Manager: {properties[3]}', 'L', ln=1)
	pdf.cell(0, 5, f'Labor: {properties[4]}', 'L', ln=1)
	pdf.ln(10) 
	pdf.cell(0, 5, f'Equipments report', 'C', ln=1)	
	# Line break
	pdf.ln(15)
			
	# table header
	pdf.table_header(['Name', 'Unit price', 'Quantity', 'Amount'], align=Align.C)
	# table rows
	for equipment_row in data_equipments:
		pdf.table_row(equipment_row, align=Align.C)		
	#Add totals
	pdf.set_font('Arial', 'B', 10)
	if len(total_equipment) > 0:
		total_amount = total_equipment[0]
		pdf.table_row(['', '', 'Total', total_amount], align=Align.C)
	else:	
		pdf.table_row(['', '', 'Total', 0], align=Align.C)					
				
	return pdf.output()
	
@app.get("/pdf_equipment_report_for_labor_id/{labor_id}", status_code=status.HTTP_201_CREATED)  
async def pdf_equipment_report_for_labor_id(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
						labor_id: str, db: Session = Depends(get_db)):		
	headers = {'Content-Disposition': 'attachment; filename="equipments.pdf"'} 
	output = report_equipments_by_labor_id(labor_id, db)	
	return Response(bytes(output), headers=headers, media_type='application/pdf')

def report_tasks_by_labor_id(labor_id: str, db: Session):

	db_project_labor = db.query(
		models.Project.project_name,
		models.Project.desc_proj,
		models.Project.enddate_proj,
		models.Project.manager,
		models.Labor.type
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).filter(
		models.Labor.id == labor_id
	).first()
	
	db_all_tasks = db.query(
		models.Task.description,
		models.Task.mechanicals,
		models.Task.hour,					
		models.Task.hour_men,
		models.Task.task_price,
	).select_from(
		models.Task
	).filter(
		models.Task.is_active == True
	).filter_by(
		labor_task_id = labor_id		
	).all()
	
	db_task_total = db.query(
		func.sum(models.Task.hour_men).label('hour_men'),		
		func.sum(models.Task.task_price).label('task_price'),
	).select_from(
		models.Labor
	).join(
		models.Task, models.Labor.id == models.Task.labor_task_id
	).filter(
		models.Labor.id == labor_id
	).all()	
		
	properties = formar_query_dict(db_project_labor)
	data_task = formar_query(db_all_tasks)
	totals_task = formar_query_totals(db_task_total)
	
	#Create table
	pdf = PDFTable()		
	#Setup page style
	pdf.alias_nb_pages()
	#Setup configuration
	#HEADER
	#Add image
	pdf.image('./logo.png', x=10, y=8, w=10)
	# Top margin: move 85 down
	pdf.ln(15) 			 
	pdf.cell(0, 5, f'Project name: {properties[0]}', 'L', ln=1)
	pdf.cell(0, 5, f'Work description: {properties[1]}', 'L', ln=1)
	pdf.cell(0, 5, f'End date: {properties[2]}', 'L', ln=1)
	pdf.cell(0, 5, f'Manager: {properties[3]}', 'L', ln=1)
	pdf.cell(0, 5, f'Labor: {properties[4]}', 'L', ln=1)
	pdf.ln(10) 
	pdf.cell(0, 5, f'Tasks report', 'C', ln=1)	
	# Line break
	pdf.ln(15)
			
	# table header
	pdf.table_header(['Description', 'Mechanicals', 'Hour', 'Hour/Men', 'Price'], align=Align.C)
	# table rows
	for task_row in data_task:
		pdf.table_row(task_row, align=Align.C)		
	#Add totals
	pdf.set_font('Arial', 'B', 10)
	if len(totals_task) > 0:
		total_men = totals_task[0]
		total_task = totals_task[1]
		pdf.table_row(['', '', 'Totals', total_men, total_task], align=Align.C)
	else:	
		pdf.table_row(['', '', 'Totals', 0, 0], align=Align.C)			
				
	return pdf.output()
	
@app.get("/pdf_task_report_for_labor_id/{labor_id}", status_code=status.HTTP_201_CREATED)  
async def pdf_task_report_for_labor_id(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					labor_id: str, db: Session = Depends(get_db)):		
	headers = {'Content-Disposition': 'attachment; filename="tasks.pdf"'} 
	output = report_tasks_by_labor_id(labor_id, db)	
	return Response(bytes(output), headers=headers, media_type='application/pdf')

def report_materials_by_labor_id(labor_id: str, db: Session):

	db_project_labor = db.query(
		models.Project.project_name,
		models.Project.desc_proj,
		models.Project.enddate_proj,
		models.Project.manager,
		models.Labor.type
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).filter(
		models.Labor.id == labor_id
	).first()
	
	db_all_materials = db.query(
		models.Material.material_name,
		models.Material.material_type,
		models.Material.material_quantity,					
		models.Material.material_price,
		models.Material.material_amount,
	).select_from(
		models.Material
	).filter_by(
		labor_material_id = labor_id		
	).all()
	
	db_material_total = db.query(
		func.sum(models.Material.material_amount).label('material_amount'),
	).select_from(
		models.Labor
	).join(
		models.Material, models.Labor.id == models.Material.labor_material_id
	).filter(
		models.Labor.id == labor_id
	).all()	
		
	properties = formar_query_dict(db_project_labor)
	data_material = formar_query(db_all_materials)
	total_material = formar_query_totals(db_material_total)
	
	#Create table
	pdf = PDFTable()		
	#Setup page style
	pdf.alias_nb_pages()
	#Setup configuration
	#HEADER
	#Add image
	pdf.image('./logo.png', x=10, y=8, w=10)
	# Top margin: move 85 down
	pdf.ln(15) 			 
	pdf.cell(0, 5, f'Project name: {properties[0]}', 'L', ln=1)
	pdf.cell(0, 5, f'Work description: {properties[1]}', 'L', ln=1)
	pdf.cell(0, 5, f'End date: {properties[2]}', 'L', ln=1)
	pdf.cell(0, 5, f'Manager: {properties[3]}', 'L', ln=1)
	pdf.cell(0, 5, f'Labor: {properties[4]}', 'L', ln=1)
	pdf.ln(10) 
	pdf.cell(0, 5, f'Materials report', 'C', ln=1)	
	# Line break
	pdf.ln(15)
			
	# table header
	pdf.table_header(['Name', 'Type', 'Quantity', 'Price', 'Amount'], align=Align.C)
	# table rows
	for material_row in data_material:
		pdf.table_row(material_row, align=Align.C)		
	#Add totals
	pdf.set_font('Arial', 'B', 10)
	if len(total_material) > 0:
		total_amount = total_material[0]
		pdf.table_row(['', '', '', 'Total', total_amount], align=Align.C)
	else:	
		pdf.table_row(['', '', '', 'Total', 0], align=Align.C)			
				
	return pdf.output()
	
@app.get("/pdf_materials_report_for_labor_id/{labor_id}", status_code=status.HTTP_201_CREATED)  
async def pdf_materials_report_for_labor_id(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					labor_id: str, db: Session = Depends(get_db)):		
	headers = {'Content-Disposition': 'attachment; filename="materials.pdf"'} 
	output = report_materials_by_labor_id(labor_id, db)	
	return Response(bytes(output), headers=headers, media_type='application/pdf')

def report_by_labor_id(labor_id: str, db: Session): #= Depends(get_db)
	
	db_project_labor = db.query(
		models.Project.project_name,
		models.Project.desc_proj,
		models.Project.enddate_proj,
		models.Project.manager,
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).filter(
		models.Labor.id == labor_id
	).first()

	properties = formar_query_dict(db_project_labor)
	
	#Create table
	pdf = PDFTable()		
	#Setup page style
	pdf.alias_nb_pages()
	#Setup configuration
	#pdf.set_font('helvetica', 12)
	pdf.set_font('Arial', '', 10)
	#HEADER
	#Add image
	pdf.image('./logo.png', x=10, y=8, w=10)
	# Top margin: move 85 down
	pdf.ln(15) 			 
	pdf.cell(0, 5, f'Project name: {properties[0]}', 'L', ln=1)
	pdf.cell(0, 5, f'Work description: {properties[1]}', 'L', ln=1)
	pdf.cell(0, 5, f'End date: {properties[2]}', 'L', ln=1)
	pdf.cell(0, 5, f'Manager: {properties[3]}', 'L', ln=1)
	pdf.ln(10) 
	pdf.cell(0, 5, f'Summary report', 'C', ln=1)	
	# Line break
	pdf.ln(15)
	
	#BODY
	#Compute data
	db_task_summary = db.query(
			models.Labor.type,
			func.count(models.Task.id).label('task_number'),
			func.sum(models.Task.hour_men).label('hour_men'),			
			func.sum(models.Task.task_price).label('task_price'),			
		).join(models.Task, models.Labor.id == models.Task.labor_task_id
		).filter(models.Task.is_active == True
		).filter_by(labor_task_id = labor_id
		).all()	
		
	db_task_total = db.query(
		func.sum(models.Task.hour_men).label('hour_men'),		
		func.sum(models.Task.task_price).label('task_price'),
	).select_from(
		models.Labor
	).join(
		models.Task, models.Labor.id == models.Task.labor_task_id
	).filter(
		models.Task.is_active == True
	).filter(
		models.Labor.id == labor_id
	).all()	
		
	data_task = formar_query(db_task_summary)	
	totals_task = formar_query_totals(db_task_total)
	#Create table
	# table header
	pdf.table_header(['Labor', '# Tasks', 'Hour/men', 'Price'], align=Align.C)
	# table rows
	for task in data_task:
		pdf.table_row(task, align=Align.C)		
	#Add totals
	pdf.set_font('Arial', 'B', 10)
	if len(totals_task) > 0:
		total_men = totals_task[0]
		total_task = totals_task[1]
		pdf.table_row(['', 'Totals', total_men, total_task], align=Align.C)
	else:	
		pdf.table_row(['', 'Totals', 0, 0], align=Align.C)
	
	#----------------------------------
	#Create table
	pdf.add_page()
	#Setup configuration
	#pdf.set_font('helvetica', 12)	
	#HEADER
	#Add image
	pdf.image('./logo.png', x=10, y=8, w=10)
	pdf.set_font('Arial', '', 10)
	# Top margin: move 85 down
	pdf.ln(15) 			 
	pdf.cell(0, 5, f'Project name: {properties[0]}', 'L', ln=1)
	pdf.cell(0, 5, f'Work description: {properties[1]}', 'L', ln=1)
	pdf.cell(0, 5, f'End date: {properties[2]}', 'L', ln=1)
	pdf.cell(0, 5, f'Manager: {properties[3]}', 'L', ln=1)
	pdf.ln(10) 
	pdf.cell(0, 5, f'Summary report', 'C', ln=1)	
	# Line break
	pdf.ln(15)
	
	#Compute data
	db_equipment_summary = db.query(
			models.Labor.type,
			func.count(models.Equipment.id).label('equipment_number'),
			func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
		).join(models.Equipment, models.Labor.id == models.Equipment.labor_equipment_id
		).filter_by(labor_equipment_id = labor_id
		).all()	
	
	db_equipment_total = db.query(
		func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
	).select_from(
		models.Labor
	).join(
		models.Equipment, models.Labor.id == models.Equipment.labor_equipment_id
	).filter(
		models.Labor.id == labor_id
	).all()	
	
	data_equipment = formar_query(db_equipment_summary)
	total_equipment = formar_query_totals(db_equipment_total)		
	#BODY
	# table header
	pdf.table_header(['Labor', '# Equipments', 'Amount'], align=Align.C)
	# table rows
	for equipment in data_equipment:
		pdf.table_row(equipment, align=Align.C)	
	#Add totals
	pdf.set_font('Arial', 'B', 10)
	if len(total_equipment) > 0:
		total_amount = total_equipment[0]
		pdf.table_row(['', 'Total', total_amount], align=Align.C)
	else:	
		pdf.table_row(['', 'Total', 0], align=Align.C)	
	
	#----------------------------------
	#Create table
	pdf.add_page()
	#Setup configuration
	#pdf.set_font('helvetica', 'b', 12)	
	#HEADER
	#Add image
	pdf.image('./logo.png', x=10, y=8, w=10)
	pdf.set_font('Arial', '', 10)
	# Top margin: move 85 down
	pdf.ln(15) 			 
	pdf.cell(0, 5, f'Project name: {properties[0]}', 'L', ln=1)
	pdf.cell(0, 5, f'Work description: {properties[1]}', 'L', ln=1)
	pdf.cell(0, 5, f'End date: {properties[2]}', 'L', ln=1)
	pdf.cell(0, 5, f'Manager: {properties[3]}', 'L', ln=1)
	pdf.ln(10) 
	pdf.cell(0, 5, f'Summary report', 'C', ln=1)	
	# Line break
	pdf.ln(15)
	
	#Compute data
	db_material_summary = db.query(
			models.Labor.type,
			models.Material.material_type,
			func.count(models.Material.id).label('material_number'),
			func.sum(models.Material.material_amount).label('material_amount'),
		).join(models.Material, models.Labor.id == models.Material.labor_material_id
		).filter_by(labor_material_id = labor_id
		).group_by(models.Material.material_type				
		).all()	

	db_material_total = db.query(
		func.sum(models.Material.material_amount).label('material_amount'),
	).select_from(
		models.Labor
	).join(
		models.Material, models.Labor.id == models.Material.labor_material_id
	).filter(
		models.Labor.id == labor_id
	).all()	
		
	data_material = formar_query(db_material_summary)
	total_material = formar_query_totals(db_material_total)		
	#BODY
	# table header
	pdf.table_header(['Labor', 'Type', '# Materials', 'Amount'], align=Align.C)
	# table rows	
	for material in data_material:
		pdf.table_row(material, align=Align.C)	
	#Add totals
	pdf.set_font('Arial', 'B', 10)
	if len(total_material) > 0:
		total_amount = total_material[0]
		pdf.table_row(['', '', 'Total', total_amount], align=Align.C)
	else:	
		pdf.table_row(['', '', 'Total', 0], align=Align.C)		
	
	return pdf.output()
	
@app.get("/pdf_report_for_labor_id/{labor_id}", status_code=status.HTTP_201_CREATED)  
async def pdf_report_for_labor_id(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					labor_id: str, db: Session = Depends(get_db)):		
	headers = {'Content-Disposition': 'attachment; filename="output.pdf"'} #inline / attachment
	output = report_by_labor_id(labor_id, db)	
	return Response(bytes(output), headers=headers, media_type='application/pdf')

def report_by_project_id(project_id: str, db: Session):
	
	db_project_desc = db.query(
		models.Project.project_name,
		models.Project.desc_proj,
		models.Project.enddate_proj,
		models.Project.manager,
	).select_from(
		models.Project
	).filter(
		models.Project.id == project_id
	).first()
	
	sub_task = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('task_number'),
		func.sum(models.Task.hour_men).label('hour_men'),
		func.sum(models.Task.task_price).label('task_price'),
	).filter(
		models.Task.is_active == True
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	sub_equipment = db.query(
		models.Equipment.labor_equipment_id.label('labor_id'),		
		func.count(models.Equipment.id).label('equipment_number'),
		func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
	).group_by(
		models.Equipment.labor_equipment_id
	).subquery()
	
	sub_material = db.query(
		models.Material.labor_material_id.label('labor_id'),
		models.Material.material_type.label('material_type'),
		func.count(models.Material.id).label('material_number'),
		func.sum(models.Material.material_amount).label('material_amount'),
	).group_by(
		models.Material.labor_material_id, models.Material.material_type
	).subquery()
	
	db_project_summary = db.query(
		models.Project.project_name,
		models.Labor.type,
		func.count(case([(sub_task.c.task_number == None, 0)], else_= sub_task.c.task_number)).label('task_number'),
		func.sum(case([(sub_task.c.hour_men == None, 0)], else_= sub_task.c.hour_men)).label('hour_men'),
		func.sum(case([(sub_task.c.task_price == None, 0)], else_= sub_task.c.task_price)).label('task_price'),
		func.sum(case([(sub_equipment.c.equipment_number == None, 0)], else_= sub_equipment.c.equipment_number)).label('equipment_number'),
		func.sum(case([(sub_equipment.c.equipment_amount == None, 0)], else_= sub_equipment.c.equipment_amount)).label('equipment_amount'),
		func.sum(case([(sub_material.c.material_number == None, 0)], else_= sub_material.c.material_number)).label('material_number'),
		func.sum(case([(sub_material.c.material_amount == None, 0)], else_= sub_material.c.material_amount)).label('material_amount'),
		func.sum(
			case([(sub_task.c.task_price == None, 0)], else_= sub_task.c.task_price) +
			case([(sub_equipment.c.equipment_amount == None, 0)], else_= sub_equipment.c.equipment_amount) +
			case([(sub_material.c.material_amount == None, 0)], else_= sub_material.c.material_amount)
		).label('Total_amount')
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).outerjoin(
		sub_equipment, models.Labor.id == sub_equipment.c.labor_id
	).outerjoin(
		sub_task, models.Labor.id == sub_task.c.labor_id
	).outerjoin(
		sub_material, models.Labor.id == sub_material.c.labor_id
	).filter(
		models.Labor.is_active == True
	).filter(
		models.Project.id == project_id 		
	).order_by(
		models.Labor.type		
	).group_by(
		models.Labor.id		
	).all()
	
	db_project_total = db.query(
		func.count(case([(sub_task.c.task_number == None, 0)], else_= sub_task.c.task_number)).label('task_number'),
		func.sum(case([(sub_task.c.hour_men == None, 0)], else_= sub_task.c.hour_men)).label('hour_men'),
		func.sum(case([(sub_task.c.task_price == None, 0)], else_= sub_task.c.task_price)).label('task_price'),
		func.sum(case([(sub_equipment.c.equipment_number == None, 0)], else_= sub_equipment.c.equipment_number)).label('equipment_number'),
		func.sum(case([(sub_equipment.c.equipment_amount == None, 0)], else_= sub_equipment.c.equipment_amount)).label('equipment_amount'),
		func.sum(case([(sub_material.c.material_number == None, 0)], else_= sub_material.c.material_number)).label('material_number'),
		func.sum(case([(sub_material.c.material_amount == None, 0)], else_= sub_material.c.material_amount)).label('material_amount'),
		func.sum(
			case([(sub_task.c.task_price == None, 0)], else_= sub_task.c.task_price) +
			case([(sub_equipment.c.equipment_amount == None, 0)], else_= sub_equipment.c.equipment_amount) +
			case([(sub_material.c.material_amount == None, 0)], else_= sub_material.c.material_amount)
		).label('Total_amount')
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).outerjoin(
		sub_equipment, models.Labor.id == sub_equipment.c.labor_id
	).outerjoin(
		sub_task, models.Labor.id == sub_task.c.labor_id
	).outerjoin(
		sub_material, models.Labor.id == sub_material.c.labor_id
	).filter(
		models.Project.id == project_id 		
	).filter(
		models.Labor.is_active == True
	).all()	
	
	properties = formar_query_dict(db_project_desc)
	data_projects = formar_query(db_project_summary)	
	totals_project = formar_query_totals(db_project_total)
	
	#Create table
	pdf = PDFTable()		
	#Setup page style
	pdf.alias_nb_pages()
	#Setup configuration
	#pdf.set_font('helvetica', 12)
	pdf.set_font('Arial', '', 10)
	#HEADER
	#Add image
	pdf.image('./logo.png', x=10, y=8, w=10)
	# Top margin: move 85 down
	pdf.ln(15) 			 
	pdf.cell(0, 5, f'Project name: {properties[0]}', 'L', ln=1)
	pdf.cell(0, 5, f'Work description: {properties[1]}', 'L', ln=1)
	pdf.cell(0, 5, f'End date: {properties[2]}', 'L', ln=1)
	pdf.cell(0, 5, f'Manager: {properties[3]}', 'L', ln=1)
	pdf.ln(10) 
	pdf.cell(0, 5, f'Summary report', 'C', ln=1)	
	# Line break
	pdf.ln(15)
	
	#Create table
	# table header
	pdf.table_header(['Labor', '#/Tasks', 'H/men', '$/Task', '#/Equip', '$/Equip', '#/Material', '$/Material', 'Amount'], align=Align.C)	
	for row in data_projects:
		pdf.table_row([row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9]], align=Align.C) 	
		
	#Add totals
	pdf.set_font('Arial', 'B', 10)
	if len(totals_project) > 0:
		task_number = totals_project[0]
		hour_men = totals_project[1]
		task_price = totals_project[2]
		equi_number = totals_project[3]
		equi_amount = totals_project[4]
		mat_number = totals_project[5]
		mat_amount = totals_project[6]
		Total_amount = totals_project[7]		
	
		pdf.table_row(['Totals', task_number, hour_men, task_price, equi_number, equi_amount, mat_number, mat_amount, Total_amount], align=Align.C)
	else:	
		pdf.table_row(['Totals', 0, 0, 0, 0, 0, 0, 0, 0], align=Align.C)	
	
	return pdf.output()
	
@app.get("/pdf_report_for_project_id/{project_id}", status_code=status.HTTP_201_CREATED)  
async def pdf_report_for_project_id(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					project_id: str, db: Session = Depends(get_db)):		
	headers = {'Content-Disposition': 'attachment; filename="output.pdf"'} #inline / attachment
	output = report_by_project_id(project_id, db)	
	return Response(bytes(output), headers=headers, media_type='application/pdf')
	
def report_summary_projects(db: Session):
	
	sub_task = db.query(
		models.Task.labor_task_id.label('labor_id'),		
		func.count(models.Task.id).label('task_number'),
		func.sum(models.Task.hour_men).label('hour_men'),
		func.sum(models.Task.task_price).label('task_price'),
	).filter(
		models.Task.is_active == True
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	sub_equipment = db.query(
		models.Equipment.labor_equipment_id.label('labor_id'),		
		func.count(models.Equipment.id).label('equipment_number'),
		func.sum(models.Equipment.equipment_amount).label('equipment_amount'),
	).group_by(
		models.Equipment.labor_equipment_id
	).subquery()
	
	sub_material = db.query(
		models.Material.labor_material_id.label('labor_id'),
		models.Material.material_type.label('material_type'),
		func.count(models.Material.id).label('material_number'),
		func.sum(models.Material.material_amount).label('material_amount'),
	).group_by(
		models.Material.labor_material_id, models.Material.material_type
	).subquery()
	
	db_project_summary = db.query(
		models.Project.project_name,
		models.Labor.type,
		func.count(case([(sub_task.c.task_number == None, 0)], else_= sub_task.c.task_number)).label('task_number'),
		func.sum(case([(sub_task.c.hour_men == None, 0)], else_= sub_task.c.hour_men)).label('hour_men'),
		func.sum(case([(sub_task.c.task_price == None, 0)], else_= sub_task.c.task_price)).label('task_price'),
		func.sum(case([(sub_equipment.c.equipment_number == None, 0)], else_= sub_equipment.c.equipment_number)).label('equipment_number'),
		func.sum(case([(sub_equipment.c.equipment_amount == None, 0)], else_= sub_equipment.c.equipment_amount)).label('equipment_amount'),
		func.sum(case([(sub_material.c.material_number == None, 0)], else_= sub_material.c.material_number)).label('material_number'),
		func.sum(case([(sub_material.c.material_amount == None, 0)], else_= sub_material.c.material_amount)).label('material_amount'),
		func.sum(
			case([(sub_task.c.task_price == None, 0)], else_= sub_task.c.task_price) +
			case([(sub_equipment.c.equipment_amount == None, 0)], else_= sub_equipment.c.equipment_amount) +
			case([(sub_material.c.material_amount == None, 0)], else_= sub_material.c.material_amount)
		).label('Total_amount')
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).outerjoin(
		sub_equipment, models.Labor.id == sub_equipment.c.labor_id
	).outerjoin(
		sub_task, models.Labor.id == sub_task.c.labor_id
	).outerjoin(
		sub_material, models.Labor.id == sub_material.c.labor_id
	).filter(
		models.Labor.is_active == True
	).order_by(
		models.Project.project_name, models.Labor.type		
	).group_by(
		models.Labor.id		
	).all()
	
	db_project_total = db.query(
		func.count(case([(sub_task.c.task_number == None, 0)], else_= sub_task.c.task_number)).label('task_number'),
		func.sum(case([(sub_task.c.hour_men == None, 0)], else_= sub_task.c.hour_men)).label('hour_men'),
		func.sum(case([(sub_task.c.task_price == None, 0)], else_= sub_task.c.task_price)).label('task_price'),
		func.sum(case([(sub_equipment.c.equipment_number == None, 0)], else_= sub_equipment.c.equipment_number)).label('equipment_number'),
		func.sum(case([(sub_equipment.c.equipment_amount == None, 0)], else_= sub_equipment.c.equipment_amount)).label('equipment_amount'),
		func.sum(case([(sub_material.c.material_number == None, 0)], else_= sub_material.c.material_number)).label('material_number'),
		func.sum(case([(sub_material.c.material_amount == None, 0)], else_= sub_material.c.material_amount)).label('material_amount'),
		func.sum(
			case([(sub_task.c.task_price == None, 0)], else_= sub_task.c.task_price) +
			case([(sub_equipment.c.equipment_amount == None, 0)], else_= sub_equipment.c.equipment_amount) +
			case([(sub_material.c.material_amount == None, 0)], else_= sub_material.c.material_amount)
		).label('Total_amount')
	).select_from(
		models.Project
	).join(
		models.Labor, models.Project.id == models.Labor.project_id
	).outerjoin(
		sub_equipment, models.Labor.id == sub_equipment.c.labor_id
	).outerjoin(
		sub_task, models.Labor.id == sub_task.c.labor_id
	).outerjoin(
		sub_material, models.Labor.id == sub_material.c.labor_id
	).filter(
		models.Labor.is_active == True
	).all()	
	
	data_projects = formar_query(db_project_summary)	
	totals_project = formar_query_totals(db_project_total)
	
	#Create table
	pdf = PDFTable()		
	#Setup page style
	pdf.alias_nb_pages()
	#Setup configuration
	#pdf.set_font('helvetica', 12)
	pdf.set_font('Arial', '', 10)
	#HEADER
	#Add image
	pdf.image('./logo.png', x=10, y=8, w=10)
	# Top margin: move 85 down
	pdf.ln(15) 			 
	pdf.cell(0, 5, f'Summary projects', 'C', ln=1)	
	# Line break
	pdf.ln(15)
	
	#Create table
	# table header
	pdf.table_header(['Project','Labor', '#/Tasks', 'H/men', '$/Task', '#/Equip', '$/Equip', '#/Material', '$/Material', 'Amount'], align=Align.C)
	
	name_row = ""
	for row in data_projects:
		if name_row != row[0]:
			pdf.set_font('helvetica', 'B', 9)
			pdf.cell(0, 5, row[0], 'L', ln=1)
			pdf.set_font('helvetica', '', 8)
			pdf.table_row(['', row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9]], align=Align.C)    #Add corresponding row
		else:
			pdf.table_row(['', row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9]], align=Align.C)    #Add corresponding row
		name_row = row[0] #Store the current name temporaly	
		
	#Add totals
	pdf.set_font('Arial', 'B', 10)
	if len(totals_project) > 0:
		task_number = totals_project[0]
		hour_men = totals_project[1]
		task_price = totals_project[2]
		equi_number = totals_project[3]
		equi_amount = totals_project[4]
		mat_number = totals_project[5]
		mat_amount = totals_project[6]
		Total_amount = totals_project[7]		
	
		pdf.table_row(['', 'Totals', task_number, hour_men, task_price, equi_number, equi_amount, mat_number, mat_amount, Total_amount], align=Align.C)
	else:	
		pdf.table_row(['', 'Totals', 0, 0, 0, 0, 0, 0, 0, 0], align=Align.C)	
	
	return pdf.output()
	
@app.get("/pdf_report_summary_projects/", status_code=status.HTTP_201_CREATED)  
async def pdf_report_summary_projects(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					db: Session = Depends(get_db)):		
	headers = {'Content-Disposition': 'attachment; filename="output.pdf"'} #inline / attachment
	output = report_summary_projects(db)	
	return Response(bytes(output), headers=headers, media_type='application/pdf')
