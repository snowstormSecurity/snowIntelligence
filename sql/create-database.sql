USE [master]
GO

/****** Object:  Database [snowIntelligence]    Script Date: 2020-01-20 10:22:54 ******/
CREATE DATABASE [snowIntelligence]
 CONTAINMENT = NONE
 ON  PRIMARY 
( NAME = N'snowIntelligence', FILENAME = N'E:\MSSQL\Data\snowIntelligence.mdf' , SIZE = 3072KB , MAXSIZE = UNLIMITED, FILEGROWTH = 1024KB )
 LOG ON 
( NAME = N'snowIntelligence_log', FILENAME = N'E:\MSSQL\Data\snowIntelligence_log.ldf' , SIZE = 11264KB , MAXSIZE = 2048GB , FILEGROWTH = 10%)
GO

IF (1 = FULLTEXTSERVICEPROPERTY('IsFullTextInstalled'))
begin
EXEC [snowIntelligence].[dbo].[sp_fulltext_database] @action = 'enable'
end
GO

ALTER DATABASE [snowIntelligence] SET ANSI_NULL_DEFAULT OFF 
GO

ALTER DATABASE [snowIntelligence] SET ANSI_NULLS OFF 
GO

ALTER DATABASE [snowIntelligence] SET ANSI_PADDING OFF 
GO

ALTER DATABASE [snowIntelligence] SET ANSI_WARNINGS OFF 
GO

ALTER DATABASE [snowIntelligence] SET ARITHABORT OFF 
GO

ALTER DATABASE [snowIntelligence] SET AUTO_CLOSE OFF 
GO

ALTER DATABASE [snowIntelligence] SET AUTO_SHRINK OFF 
GO

ALTER DATABASE [snowIntelligence] SET AUTO_UPDATE_STATISTICS ON 
GO

ALTER DATABASE [snowIntelligence] SET CURSOR_CLOSE_ON_COMMIT OFF 
GO

ALTER DATABASE [snowIntelligence] SET CURSOR_DEFAULT  GLOBAL 
GO

ALTER DATABASE [snowIntelligence] SET CONCAT_NULL_YIELDS_NULL OFF 
GO

ALTER DATABASE [snowIntelligence] SET NUMERIC_ROUNDABORT OFF 
GO

ALTER DATABASE [snowIntelligence] SET QUOTED_IDENTIFIER OFF 
GO

ALTER DATABASE [snowIntelligence] SET RECURSIVE_TRIGGERS OFF 
GO

ALTER DATABASE [snowIntelligence] SET  DISABLE_BROKER 
GO

ALTER DATABASE [snowIntelligence] SET AUTO_UPDATE_STATISTICS_ASYNC OFF 
GO

ALTER DATABASE [snowIntelligence] SET DATE_CORRELATION_OPTIMIZATION OFF 
GO

ALTER DATABASE [snowIntelligence] SET TRUSTWORTHY OFF 
GO

ALTER DATABASE [snowIntelligence] SET ALLOW_SNAPSHOT_ISOLATION OFF 
GO

ALTER DATABASE [snowIntelligence] SET PARAMETERIZATION SIMPLE 
GO

ALTER DATABASE [snowIntelligence] SET READ_COMMITTED_SNAPSHOT OFF 
GO

ALTER DATABASE [snowIntelligence] SET HONOR_BROKER_PRIORITY OFF 
GO

ALTER DATABASE [snowIntelligence] SET RECOVERY FULL 
GO

ALTER DATABASE [snowIntelligence] SET  MULTI_USER 
GO

ALTER DATABASE [snowIntelligence] SET PAGE_VERIFY CHECKSUM  
GO

ALTER DATABASE [snowIntelligence] SET DB_CHAINING OFF 
GO

ALTER DATABASE [snowIntelligence] SET FILESTREAM( NON_TRANSACTED_ACCESS = OFF ) 
GO

ALTER DATABASE [snowIntelligence] SET TARGET_RECOVERY_TIME = 0 SECONDS 
GO

ALTER DATABASE [snowIntelligence] SET DELAYED_DURABILITY = DISABLED 
GO

ALTER DATABASE [snowIntelligence] SET  READ_WRITE 
GO


