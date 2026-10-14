# ==============================================================================
# STAGE 1: Build & Publish
# ==============================================================================
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Copy project files first for optimal Docker layer caching
COPY ["src/SecureChat.Core/SecureChat.Core.csproj", "src/SecureChat.Core/"]
COPY ["src/SecureChat.Server/SecureChat.Server.csproj", "src/SecureChat.Server/"]

# Restore dependencies
RUN dotnet restore "src/SecureChat.Server/SecureChat.Server.csproj"

# Copy source files for Server and Core
COPY ["src/SecureChat.Core/", "src/SecureChat.Core/"]
COPY ["src/SecureChat.Server/", "src/SecureChat.Server/"]

# Publish application in Release mode
WORKDIR "/src/src/SecureChat.Server"
RUN dotnet publish "SecureChat.Server.csproj" -c Release -o /app/publish /p:UseAppHost=false

# ==============================================================================
# STAGE 2: Runtime Environment
# ==============================================================================
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

# Render uses port 10000 by default (overridden by PORT environment variable)
ENV PORT=10000
ENV ASPNETCORE_URLS=http://0.0.0.0:10000
ENV ASPNETCORE_ENVIRONMENT=Production

# Copy compiled artifacts
COPY --from=build /app/publish .

# Create local directory for fallback data store
RUN mkdir -p /app/data

EXPOSE 10000

ENTRYPOINT ["dotnet", "SecureChat.Server.dll"]
