# DB
```sh
dotnet tool update -g dotnet-ef
dotnet tool update -g dotnet-aspnet-codegenerator

dotnet ef migrations add --project DAL --startup-project WebApp --context AppDbContext InitialCreate

dotnet ef migrations   --project DAL --startup-project WebApp remove

dotnet ef database   --project DAL --startup-project WebApp update
dotnet ef database   --project DAL --startup-project WebApp drop


```

# MVC
```sh
#cd WebApp

dotnet aspnet-codegenerator controller -name [EntityName]Controller -actions -m  Domain.[EntityName] -dc AppDbContext -outDir Controllers --useDefaultLayout --useAsyncActions --referenceScriptLibraries -f

```