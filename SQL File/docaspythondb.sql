-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Máy chủ: 127.0.0.1
-- Thời gian đã tạo: Th2 25, 2026 lúc 06:19 PM
-- Phiên bản máy phục vụ: 10.4.32-MariaDB
-- Phiên bản PHP: 8.0.30

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Cơ sở dữ liệu: `docaspythondb`
--

-- --------------------------------------------------------

--
-- Cấu trúc bảng cho bảng `auth_group`
--

CREATE TABLE `auth_group` (
  `id` int(11) NOT NULL,
  `name` varchar(150) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Cấu trúc bảng cho bảng `auth_group_permissions`
--

CREATE TABLE `auth_group_permissions` (
  `id` bigint(20) NOT NULL,
  `group_id` int(11) NOT NULL,
  `permission_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Cấu trúc bảng cho bảng `auth_permission`
--

CREATE TABLE `auth_permission` (
  `id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `content_type_id` int(11) NOT NULL,
  `codename` varchar(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Đang đổ dữ liệu cho bảng `auth_permission`
--

INSERT INTO `auth_permission` (`id`, `name`, `content_type_id`, `codename`) VALUES
(1, 'Can add log entry', 1, 'add_logentry'),
(2, 'Can change log entry', 1, 'change_logentry'),
(3, 'Can delete log entry', 1, 'delete_logentry'),
(4, 'Can view log entry', 1, 'view_logentry'),
(5, 'Can add permission', 2, 'add_permission'),
(6, 'Can change permission', 2, 'change_permission'),
(7, 'Can delete permission', 2, 'delete_permission'),
(8, 'Can view permission', 2, 'view_permission'),
(9, 'Can add group', 3, 'add_group'),
(10, 'Can change group', 3, 'change_group'),
(11, 'Can delete group', 3, 'delete_group'),
(12, 'Can view group', 3, 'view_group'),
(13, 'Can add content type', 4, 'add_contenttype'),
(14, 'Can change content type', 4, 'change_contenttype'),
(15, 'Can delete content type', 4, 'delete_contenttype'),
(16, 'Can view content type', 4, 'view_contenttype'),
(17, 'Can add session', 5, 'add_session'),
(18, 'Can change session', 5, 'change_session'),
(19, 'Can delete session', 5, 'delete_session'),
(20, 'Can view session', 5, 'view_session'),
(21, 'Can add user', 6, 'add_customuser'),
(22, 'Can change user', 6, 'change_customuser'),
(23, 'Can delete user', 6, 'delete_customuser'),
(24, 'Can view user', 6, 'view_customuser'),
(25, 'Can add specialization', 7, 'add_specialization'),
(26, 'Can change specialization', 7, 'change_specialization'),
(27, 'Can delete specialization', 7, 'delete_specialization'),
(28, 'Can view specialization', 7, 'view_specialization'),
(29, 'Can add doctor reg', 8, 'add_doctorreg'),
(30, 'Can change doctor reg', 8, 'change_doctorreg'),
(31, 'Can delete doctor reg', 8, 'delete_doctorreg'),
(32, 'Can view doctor reg', 8, 'view_doctorreg'),
(33, 'Can add appointment', 9, 'add_appointment'),
(34, 'Can change appointment', 9, 'change_appointment'),
(35, 'Can delete appointment', 9, 'delete_appointment'),
(36, 'Can view appointment', 9, 'view_appointment'),
(37, 'Can add page', 10, 'add_page'),
(38, 'Can change page', 10, 'change_page'),
(39, 'Can delete page', 10, 'delete_page'),
(40, 'Can view page', 10, 'view_page');

-- --------------------------------------------------------

--
-- Cấu trúc bảng cho bảng `dasapp_appointment`
--

CREATE TABLE `dasapp_appointment` (
  `id` bigint(20) NOT NULL,
  `appointmentnumber` int(11) NOT NULL,
  `fullname` varchar(250) NOT NULL,
  `mobilenumber` varchar(11) NOT NULL,
  `email` varchar(100) NOT NULL,
  `date_of_appointment` varchar(250) NOT NULL,
  `time_of_appointment` varchar(250) NOT NULL,
  `additional_msg` longtext NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `doctor_id_id` bigint(20) NOT NULL,
  `prescription` longtext NOT NULL,
  `remark` varchar(250) NOT NULL,
  `status` varchar(200) NOT NULL,
  `recommendedtest` longtext NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Đang đổ dữ liệu cho bảng `dasapp_appointment`
--

INSERT INTO `dasapp_appointment` (`id`, `appointmentnumber`, `fullname`, `mobilenumber`, `email`, `date_of_appointment`, `time_of_appointment`, `additional_msg`, `created_at`, `updated_at`, `doctor_id_id`, `prescription`, `remark`, `status`, `recommendedtest`) VALUES
(7, 635776554, 'Phạm Khánh Trang', '0367102804', 'trangpk.22it@vku.udn.vn', '2026-02-11', '10:40', 'Nhớ bác sĩ quá', '2026-02-10 14:36:20.012264', '2026-02-25 22:41:45.900728', 8, 'Ăn uống nhiều vào ngày đủ 3 bữa nhé.', 'Bác sĩ cx nhớ em', 'Completed', 'Chăm chỉ đánh cầu và chăm sóc yêu thương Nguyên hơn nữa'),
(8, 638942542, 'Phạm Thanh Doãn', '0905829375', 'doan123@gmail.com', '2026-02-28', '10:10', 'Tôi bị chó cắn', '2026-02-25 22:51:54.784298', '2026-02-25 23:11:39.703546', 10, '0', 'Cố gắng đừng đi trộm chó hay chọc chó nữa nhé', 'Approved', '0');

-- --------------------------------------------------------

--
-- Cấu trúc bảng cho bảng `dasapp_customuser`
--

CREATE TABLE `dasapp_customuser` (
  `id` bigint(20) NOT NULL,
  `password` varchar(128) NOT NULL,
  `last_login` datetime(6) DEFAULT NULL,
  `is_superuser` tinyint(1) NOT NULL,
  `username` varchar(150) NOT NULL,
  `first_name` varchar(150) NOT NULL,
  `last_name` varchar(150) NOT NULL,
  `email` varchar(254) NOT NULL,
  `is_staff` tinyint(1) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `date_joined` datetime(6) NOT NULL,
  `user_type` varchar(50) NOT NULL,
  `profile_pic` varchar(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Đang đổ dữ liệu cho bảng `dasapp_customuser`
--

INSERT INTO `dasapp_customuser` (`id`, `password`, `last_login`, `is_superuser`, `username`, `first_name`, `last_name`, `email`, `is_staff`, `is_active`, `date_joined`, `user_type`, `profile_pic`) VALUES
(9, 'pbkdf2_sha256$600000$7euUL0I5zRJowN7R90OskX$2czpLx6BxRGOr3CoS4N1um3MA5o/uqIt4YMMxUUIOzs=', '2026-02-25 23:37:09.718120', 0, 'ntnguyen2034', 'NGUYEN TRUNG', ' NGUYEN', 'nguyenkun555@gmail.com', 0, 1, '2026-02-10 14:16:20.490778', '2', 'media/profile_pic/d9dcc2db-c5bd-44a5-aa3d-9c1a4fa6d479.jpg'),
(10, 'pbkdf2_sha256$600000$eSo8O4tOBqQTtAX3zOljyS$fUr4eLNp7i3SBVUUixESVdJXzlXNm1LpLyaVTAP4myk=', '2026-02-25 23:40:03.370120', 1, 'admin', 'NGUYEN TRUNG', 'NGUYEN', 'admin123@gmail.com', 1, 1, '2026-02-10 14:21:39.323721', '1', 'media/profile_pic/0e111958-42e7-4a3f-b395-ae8b03c7559a.jpg'),
(11, 'pbkdf2_sha256$600000$5qT4gxxeMvGxmyFcqSkWYQ$TtcsBRscQRajfMC82HL/kaqfFHt4Ank6a8hqQ7RH3po=', '2026-02-11 02:37:30.382719', 0, 'dinh123', 'NGUYEN TRUNG', ' DINH', 'dinh123@gmail.com', 0, 1, '2026-02-10 14:48:27.415817', '2', 'media/profile_pic/unnamed.jpg'),
(12, 'pbkdf2_sha256$600000$HJ05bQ2tOQ37d1rxdq0HIx$YZGEyiA6epSgEsCoZZcaIlsDXTHVoQCh0x7rQNAv6MQ=', '2026-02-25 22:58:37.775567', 0, 'ntphuoc123', 'NGÔ', 'TẤN PHƯỚC', 'ntphuoc123@gmail.com', 0, 1, '2026-02-25 16:09:20.000000', '2', 'media/profile_pic/WIN_20250712_08_39_36_Pro.jpg');

-- --------------------------------------------------------

--
-- Cấu trúc bảng cho bảng `dasapp_customuser_groups`
--

CREATE TABLE `dasapp_customuser_groups` (
  `id` bigint(20) NOT NULL,
  `customuser_id` bigint(20) NOT NULL,
  `group_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Cấu trúc bảng cho bảng `dasapp_customuser_user_permissions`
--

CREATE TABLE `dasapp_customuser_user_permissions` (
  `id` bigint(20) NOT NULL,
  `customuser_id` bigint(20) NOT NULL,
  `permission_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Cấu trúc bảng cho bảng `dasapp_doctorreg`
--

CREATE TABLE `dasapp_doctorreg` (
  `id` bigint(20) NOT NULL,
  `mobilenumber` varchar(11) NOT NULL,
  `regdate_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `admin_id` bigint(20) DEFAULT NULL,
  `specialization_id_id` bigint(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Đang đổ dữ liệu cho bảng `dasapp_doctorreg`
--

INSERT INTO `dasapp_doctorreg` (`id`, `mobilenumber`, `regdate_at`, `updated_at`, `admin_id`, `specialization_id_id`) VALUES
(8, '0397556616', '2026-02-10 14:16:20.928359', '2026-02-10 14:16:20.928359', 9, 2),
(9, '0373829873', '2026-02-10 14:48:27.820170', '2026-02-10 14:48:27.820170', 11, 13),
(10, '0123456789', '2026-02-25 16:09:20.464457', '2026-02-25 16:09:20.464457', 12, 11);

-- --------------------------------------------------------

--
-- Cấu trúc bảng cho bảng `dasapp_page`
--

CREATE TABLE `dasapp_page` (
  `id` bigint(20) NOT NULL,
  `pagetitle` varchar(250) NOT NULL,
  `address` varchar(250) NOT NULL,
  `aboutus` longtext NOT NULL,
  `email` varchar(200) NOT NULL,
  `mobilenumber` varchar(15) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Đang đổ dữ liệu cho bảng `dasapp_page`
--

INSERT INTO `dasapp_page` (`id`, `pagetitle`, `address`, `aboutus`, `email`, `mobilenumber`, `created_at`, `updated_at`) VALUES
(1, 'Webpage Details', '100 Nguyễn Thức Tự, Ngũ Hành Sơn, Đà Nẵng', 'Có khoảng 60 chuyên khoa y tế và 30 chuyên ngành phụ, khiến việc lựa chọn chuyên ngành trở nên khó khăn hơn đối với các bác sĩ. Dựa trên sở thích, bác sĩ có thể lựa chọn chuyên khoa y tế. Tuy nhiên, cần phải xem xét các yếu tố như nhu cầu, phạm vi, mức lương và số lượng chỗ học sau đại học ngành y.\r\n\r\nTrong tình huống như vậy, việc đưa ra quyết định sẽ khó khăn hơn. Tuy nhiên, quyết định của bạn rất quan trọng, có thể quyết định bạn sẽ xây dựng một sự nghiệp thành công hay thất bại. Vì vậy, hãy cẩn thận khi lựa chọn chuyên khoa y tế. Các khóa học y khoa được liệt kê dưới đây đang có nhu cầu cao và phạm vi rộng lớn tại Việt Nam.', 'nguyenkun555@gmail.com', '0397556616', '0000-00-00 00:00:00.000000', '2024-02-26 06:39:16.446263');

-- --------------------------------------------------------

--
-- Cấu trúc bảng cho bảng `dasapp_specialization`
--

CREATE TABLE `dasapp_specialization` (
  `id` bigint(20) NOT NULL,
  `sname` varchar(200) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Đang đổ dữ liệu cho bảng `dasapp_specialization`
--

INSERT INTO `dasapp_specialization` (`id`, `sname`, `created_at`, `updated_at`) VALUES
(1, 'Chỉnh hình', '2024-02-26 06:24:12.101985', '2024-02-26 06:24:12.101985'),
(2, 'Nội khoa', '2024-02-26 06:24:25.653848', '2024-02-26 06:24:25.653848'),
(3, 'Sản phụ khoa', '2024-02-26 06:24:35.592772', '2024-02-26 06:24:35.592772'),
(4, 'Da liễu', '2024-02-26 06:24:45.212670', '2024-02-26 06:24:45.212670'),
(5, 'Nhi khoa', '2024-02-26 06:24:52.493340', '2024-02-26 06:24:52.493340'),
(6, 'Chẩn đoán hình ảnh', '2024-02-26 06:25:00.364941', '2024-02-26 06:25:00.364941'),
(7, 'Phẫu thuật tổng quát', '2024-02-26 06:25:09.110658', '2024-02-26 06:25:09.110658'),
(8, 'Nhãn khoa', '2024-02-26 06:25:16.661938', '2024-02-26 06:25:16.662934'),
(9, 'Y học gia đình', '2024-02-26 06:25:27.502854', '2024-02-26 06:25:27.502854'),
(10, 'Y học lồng ngực', '2024-02-26 06:25:42.886345', '2024-02-26 06:25:42.886345'),
(11, 'Gây mê', '2024-02-26 06:25:50.029827', '2024-02-26 06:25:50.029827'),
(12, 'Bệnh lý', '2024-02-26 06:25:58.369617', '2024-02-26 06:25:58.369617'),
(13, 'Tai Mũi Họng', '2024-02-26 06:26:05.020793', '2024-02-26 06:26:05.020793');

-- --------------------------------------------------------

--
-- Cấu trúc bảng cho bảng `django_admin_log`
--

CREATE TABLE `django_admin_log` (
  `id` int(11) NOT NULL,
  `action_time` datetime(6) NOT NULL,
  `object_id` longtext DEFAULT NULL,
  `object_repr` varchar(200) NOT NULL,
  `action_flag` smallint(5) UNSIGNED NOT NULL,
  `change_message` longtext NOT NULL,
  `content_type_id` int(11) DEFAULT NULL,
  `user_id` bigint(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Đang đổ dữ liệu cho bảng `django_admin_log`
--

INSERT INTO `django_admin_log` (`id`, `action_time`, `object_id`, `object_repr`, `action_flag`, `change_message`, `content_type_id`, `user_id`) VALUES
(1, '2026-02-10 14:22:11.133950', '1', 'admin', 3, '', 6, 10),
(2, '2026-02-10 14:44:41.684220', '6', 'Appointment #749133529 - Garima Singh', 3, '', 9, 10),
(3, '2026-02-10 14:44:46.985814', '5', 'Appointment #718119677 - Amit', 3, '', 9, 10),
(4, '2026-02-10 14:44:50.700516', '4', 'Appointment #288217941 - Tanu Sharma', 3, '', 9, 10),
(5, '2026-02-10 14:44:54.960420', '3', 'Appointment #566162414 - Rakesh Sharma', 3, '', 9, 10),
(6, '2026-02-10 14:44:58.296153', '2', 'Appointment #425778070 - Ram Chandra', 3, '', 9, 10),
(7, '2026-02-10 14:45:01.644348', '1', 'Appointment #925833328 - Harish Kumar', 3, '', 9, 10),
(8, '2026-02-25 16:11:11.188799', '3', 'abir123', 3, '', 6, 10),
(9, '2026-02-25 16:11:20.171413', '7', 'drak30', 3, '', 6, 10),
(10, '2026-02-25 16:11:33.134216', '2', 'gar123', 3, '', 6, 10),
(11, '2026-02-25 16:11:38.167518', '5', 'har123', 3, '', 6, 10),
(12, '2026-02-25 16:11:42.373055', '8', 'johndeo12', 3, '', 6, 10),
(13, '2026-02-25 16:12:10.888546', '12', 'ntphuoc123', 2, '[{\"changed\": {\"fields\": [\"Username\", \"First name\", \"Last name\"]}}]', 6, 10),
(14, '2026-02-25 16:12:16.029723', '6', 'renu123', 3, '', 6, 10),
(15, '2026-02-25 16:12:21.349472', '4', 'som123', 3, '', 6, 10),
(16, '2026-02-25 16:16:11.703070', '12', 'ntphuoc123', 2, '[{\"changed\": {\"fields\": [\"First name\", \"Last name\", \"Email address\"]}}]', 6, 10);

-- --------------------------------------------------------

--
-- Cấu trúc bảng cho bảng `django_content_type`
--

CREATE TABLE `django_content_type` (
  `id` int(11) NOT NULL,
  `app_label` varchar(100) NOT NULL,
  `model` varchar(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Đang đổ dữ liệu cho bảng `django_content_type`
--

INSERT INTO `django_content_type` (`id`, `app_label`, `model`) VALUES
(1, 'admin', 'logentry'),
(3, 'auth', 'group'),
(2, 'auth', 'permission'),
(4, 'contenttypes', 'contenttype'),
(9, 'dasapp', 'appointment'),
(6, 'dasapp', 'customuser'),
(8, 'dasapp', 'doctorreg'),
(10, 'dasapp', 'page'),
(7, 'dasapp', 'specialization'),
(5, 'sessions', 'session');

-- --------------------------------------------------------

--
-- Cấu trúc bảng cho bảng `django_migrations`
--

CREATE TABLE `django_migrations` (
  `id` bigint(20) NOT NULL,
  `app` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `applied` datetime(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Đang đổ dữ liệu cho bảng `django_migrations`
--

INSERT INTO `django_migrations` (`id`, `app`, `name`, `applied`) VALUES
(1, 'contenttypes', '0001_initial', '2024-02-26 06:18:09.420094'),
(2, 'contenttypes', '0002_remove_content_type_name', '2024-02-26 06:18:09.481700'),
(3, 'auth', '0001_initial', '2024-02-26 06:18:09.719886'),
(4, 'auth', '0002_alter_permission_name_max_length', '2024-02-26 06:18:09.767781'),
(5, 'auth', '0003_alter_user_email_max_length', '2024-02-26 06:18:09.777756'),
(6, 'auth', '0004_alter_user_username_opts', '2024-02-26 06:18:09.785828'),
(7, 'auth', '0005_alter_user_last_login_null', '2024-02-26 06:18:09.792851'),
(8, 'auth', '0006_require_contenttypes_0002', '2024-02-26 06:18:09.795805'),
(9, 'auth', '0007_alter_validators_add_error_messages', '2024-02-26 06:18:09.802735'),
(10, 'auth', '0008_alter_user_username_max_length', '2024-02-26 06:18:09.809677'),
(11, 'auth', '0009_alter_user_last_name_max_length', '2024-02-26 06:18:09.816658'),
(12, 'auth', '0010_alter_group_name_max_length', '2024-02-26 06:18:09.828747'),
(13, 'auth', '0011_update_proxy_permissions', '2024-02-26 06:18:09.836726'),
(14, 'auth', '0012_alter_user_first_name_max_length', '2024-02-26 06:18:09.844320'),
(15, 'dasapp', '0001_initial', '2024-02-26 06:18:10.162316'),
(16, 'admin', '0001_initial', '2024-02-26 06:18:10.322744'),
(17, 'admin', '0002_logentry_remove_auto_add', '2024-02-26 06:18:10.335918'),
(18, 'admin', '0003_logentry_add_action_flag_choices', '2024-02-26 06:18:10.349882'),
(19, 'dasapp', '0002_alter_customuser_user_type', '2024-02-26 06:18:10.359246'),
(20, 'dasapp', '0003_specialization_alter_customuser_user_type', '2024-02-26 06:18:10.384022'),
(21, 'dasapp', '0004_alter_customuser_user_type_doctorreg', '2024-02-26 06:18:10.517449'),
(22, 'dasapp', '0005_alter_customuser_user_type_appointment', '2024-02-26 06:18:10.638866'),
(23, 'dasapp', '0006_alter_customuser_user_type', '2024-02-26 06:18:10.652829'),
(24, 'dasapp', '0007_alter_appointment_date_of_appointment_and_more', '2024-02-26 06:18:10.764269'),
(25, 'dasapp', '0008_alter_appointment_email', '2024-02-26 06:18:15.083492'),
(26, 'dasapp', '0009_appointment_prescription_appointment_remark_and_more', '2024-02-26 06:18:15.136642'),
(27, 'dasapp', '0010_alter_appointment_prescription_and_more', '2024-02-26 06:18:15.156898'),
(28, 'dasapp', '0011_appointment_recommendedtest_and_more', '2024-02-26 06:18:15.278690'),
(29, 'dasapp', '0012_alter_customuser_user_type', '2024-02-26 06:18:15.290900'),
(30, 'dasapp', '0013_page_alter_customuser_user_type', '2024-02-26 06:18:15.312347'),
(31, 'dasapp', '0014_remove_doctorreg_profile_pic', '2024-02-26 06:18:15.334639'),
(32, 'dasapp', '0015_doctorreg_profile_pic', '2024-02-26 06:18:15.372634'),
(33, 'dasapp', '0016_remove_doctorreg_profile_pic', '2024-02-26 06:18:15.390847'),
(34, 'sessions', '0001_initial', '2024-02-26 06:18:15.425865'),
(35, 'dasapp', '0017_alter_customuser_user_type', '2026-02-10 14:12:43.129831'),
(36, 'dasapp', '0018_alter_page_mobilenumber', '2026-02-25 16:04:34.047915');

-- --------------------------------------------------------

--
-- Cấu trúc bảng cho bảng `django_session`
--

CREATE TABLE `django_session` (
  `session_key` varchar(40) NOT NULL,
  `session_data` longtext NOT NULL,
  `expire_date` datetime(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Đang đổ dữ liệu cho bảng `django_session`
--

INSERT INTO `django_session` (`session_key`, `session_data`, `expire_date`) VALUES
('13fzdfbm8tr9v9rtu8ughntqp71sguqo', '.eJxVjDEOwjAMRe-SGUVOUXHMyM4ZIjuOaQG1UtNOFXdHkTrA-t97f3eJt3VIWy1LGtVdXXCn3004v8rUgD55esw-z9O6jOKb4g9a_X3W8r4d7t_BwHVo9fnCaBKZUAHVOislE5NE5J6kB9MgBtGIpMu5y4ASFcgAAxZQ9_kCF385BQ:1rer8c:Di632v5ncN1k7kirlnXNl97SHHuPv004lb5PHg79Fxc', '2024-03-12 06:40:26.826027'),
('lv4jm2dr50ebae6qbww9kwkkd3rkeoel', '.eJxVjM0OwiAQhN-FsyGFIrt69N5nIMvPStVAUtqT8d2lSQ96mmS-b-YtHG1rdltLi5ujuAolTr-dp_BMZQfxQeVeZahlXWYvd0UetMmpxvS6He7fQaaW-_rMMCqMYC35YEyEYaTLoFkjKEI2qEMCC8FwV5g9G5-QQg_N6McoPl_daDh7:1riHdO:fdn9SQZfZ_8Ht0HW8746TQy-Qg2okH-WbUlVJ7-IQIE', '2024-03-21 17:34:22.101361'),
('mly9m8ehhc2auasu5hjpyzrwgnjn0dwh', '.eJxVjEEOwiAQRe_C2pAOUgou3fcMZIZhpGpoUtqV8e7apAvd_vfef6mI21ri1vISJ1YXBZ06_Y6E6ZHrTviO9TbrNNd1mUjvij5o0-PM-Xk93L-Dgq18a0eMgwh6HwZrMnkLmTsKANYhiTXS85nFGMHE7MSKBzKBUp8RUmL1_gAxODmw:1vvHvf:69tZ8vCtGq_YKShD9tLKTzwGbkCPG8YngbGy5EVffOo', '2026-03-11 23:40:03.374496'),
('orq7hxqffhou3bkacjouz53w7s3h4mlx', '.eJxVjMsOwiAQRf-FtSHIhJdL934DGZhBqgaS0q4a_12bdKHbe865m4i4LjWug-c4kbgIEKffLWF-ctsBPbDdu8y9LfOU5K7Igw5568Sv6-H-HVQc9VtrNIScvQ8pZW8dgy9GExjFZwLF3gZwgFaTM0U5sg6DcgU9kDLaFvH-AO33N7k:1rerDn:iuZPwpMypM39VwePXfVCoyHoa2-KQyY6bMBsDJ-Dty4', '2024-03-12 06:45:47.364618');

--
-- Chỉ mục cho các bảng đã đổ
--

--
-- Chỉ mục cho bảng `auth_group`
--
ALTER TABLE `auth_group`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `name` (`name`);

--
-- Chỉ mục cho bảng `auth_group_permissions`
--
ALTER TABLE `auth_group_permissions`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `auth_group_permissions_group_id_permission_id_0cd325b0_uniq` (`group_id`,`permission_id`),
  ADD KEY `auth_group_permissio_permission_id_84c5c92e_fk_auth_perm` (`permission_id`);

--
-- Chỉ mục cho bảng `auth_permission`
--
ALTER TABLE `auth_permission`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `auth_permission_content_type_id_codename_01ab375a_uniq` (`content_type_id`,`codename`);

--
-- Chỉ mục cho bảng `dasapp_appointment`
--
ALTER TABLE `dasapp_appointment`
  ADD PRIMARY KEY (`id`),
  ADD KEY `dasapp_appointment_doctor_id_id_045c6f58_fk_dasapp_doctorreg_id` (`doctor_id_id`);

--
-- Chỉ mục cho bảng `dasapp_customuser`
--
ALTER TABLE `dasapp_customuser`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- Chỉ mục cho bảng `dasapp_customuser_groups`
--
ALTER TABLE `dasapp_customuser_groups`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `dasapp_customuser_groups_customuser_id_group_id_e4fe99d3_uniq` (`customuser_id`,`group_id`),
  ADD KEY `dasapp_customuser_groups_group_id_cecd6c59_fk_auth_group_id` (`group_id`);

--
-- Chỉ mục cho bảng `dasapp_customuser_user_permissions`
--
ALTER TABLE `dasapp_customuser_user_permissions`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `dasapp_customuser_user_p_customuser_id_permission_f6b0a96d_uniq` (`customuser_id`,`permission_id`),
  ADD KEY `dasapp_customuser_us_permission_id_28ebaabc_fk_auth_perm` (`permission_id`);

--
-- Chỉ mục cho bảng `dasapp_doctorreg`
--
ALTER TABLE `dasapp_doctorreg`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `admin_id` (`admin_id`),
  ADD KEY `dasapp_doctorreg_specialization_id_id_053c14bd_fk_dasapp_sp` (`specialization_id_id`);

--
-- Chỉ mục cho bảng `dasapp_page`
--
ALTER TABLE `dasapp_page`
  ADD PRIMARY KEY (`id`);

--
-- Chỉ mục cho bảng `dasapp_specialization`
--
ALTER TABLE `dasapp_specialization`
  ADD PRIMARY KEY (`id`);

--
-- Chỉ mục cho bảng `django_admin_log`
--
ALTER TABLE `django_admin_log`
  ADD PRIMARY KEY (`id`),
  ADD KEY `django_admin_log_content_type_id_c4bce8eb_fk_django_co` (`content_type_id`),
  ADD KEY `django_admin_log_user_id_c564eba6_fk_dasapp_customuser_id` (`user_id`);

--
-- Chỉ mục cho bảng `django_content_type`
--
ALTER TABLE `django_content_type`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `django_content_type_app_label_model_76bd3d3b_uniq` (`app_label`,`model`);

--
-- Chỉ mục cho bảng `django_migrations`
--
ALTER TABLE `django_migrations`
  ADD PRIMARY KEY (`id`);

--
-- Chỉ mục cho bảng `django_session`
--
ALTER TABLE `django_session`
  ADD PRIMARY KEY (`session_key`),
  ADD KEY `django_session_expire_date_a5c62663` (`expire_date`);

--
-- AUTO_INCREMENT cho các bảng đã đổ
--

--
-- AUTO_INCREMENT cho bảng `auth_group`
--
ALTER TABLE `auth_group`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT cho bảng `auth_group_permissions`
--
ALTER TABLE `auth_group_permissions`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT cho bảng `auth_permission`
--
ALTER TABLE `auth_permission`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=41;

--
-- AUTO_INCREMENT cho bảng `dasapp_appointment`
--
ALTER TABLE `dasapp_appointment`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- AUTO_INCREMENT cho bảng `dasapp_customuser`
--
ALTER TABLE `dasapp_customuser`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=13;

--
-- AUTO_INCREMENT cho bảng `dasapp_customuser_groups`
--
ALTER TABLE `dasapp_customuser_groups`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT cho bảng `dasapp_customuser_user_permissions`
--
ALTER TABLE `dasapp_customuser_user_permissions`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT cho bảng `dasapp_doctorreg`
--
ALTER TABLE `dasapp_doctorreg`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- AUTO_INCREMENT cho bảng `dasapp_page`
--
ALTER TABLE `dasapp_page`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT cho bảng `dasapp_specialization`
--
ALTER TABLE `dasapp_specialization`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=15;

--
-- AUTO_INCREMENT cho bảng `django_admin_log`
--
ALTER TABLE `django_admin_log`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=17;

--
-- AUTO_INCREMENT cho bảng `django_content_type`
--
ALTER TABLE `django_content_type`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- AUTO_INCREMENT cho bảng `django_migrations`
--
ALTER TABLE `django_migrations`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=37;

--
-- Các ràng buộc cho các bảng đã đổ
--

--
-- Các ràng buộc cho bảng `auth_group_permissions`
--
ALTER TABLE `auth_group_permissions`
  ADD CONSTRAINT `auth_group_permissio_permission_id_84c5c92e_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`),
  ADD CONSTRAINT `auth_group_permissions_group_id_b120cbf9_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`);

--
-- Các ràng buộc cho bảng `auth_permission`
--
ALTER TABLE `auth_permission`
  ADD CONSTRAINT `auth_permission_content_type_id_2f476e4b_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`);

--
-- Các ràng buộc cho bảng `dasapp_appointment`
--
ALTER TABLE `dasapp_appointment`
  ADD CONSTRAINT `dasapp_appointment_doctor_id_id_045c6f58_fk_dasapp_doctorreg_id` FOREIGN KEY (`doctor_id_id`) REFERENCES `dasapp_doctorreg` (`id`);

--
-- Các ràng buộc cho bảng `dasapp_customuser_groups`
--
ALTER TABLE `dasapp_customuser_groups`
  ADD CONSTRAINT `dasapp_customuser_gr_customuser_id_e4c9b5ff_fk_dasapp_cu` FOREIGN KEY (`customuser_id`) REFERENCES `dasapp_customuser` (`id`),
  ADD CONSTRAINT `dasapp_customuser_groups_group_id_cecd6c59_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`);

--
-- Các ràng buộc cho bảng `dasapp_customuser_user_permissions`
--
ALTER TABLE `dasapp_customuser_user_permissions`
  ADD CONSTRAINT `dasapp_customuser_us_customuser_id_5a276bdd_fk_dasapp_cu` FOREIGN KEY (`customuser_id`) REFERENCES `dasapp_customuser` (`id`),
  ADD CONSTRAINT `dasapp_customuser_us_permission_id_28ebaabc_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`);

--
-- Các ràng buộc cho bảng `dasapp_doctorreg`
--
ALTER TABLE `dasapp_doctorreg`
  ADD CONSTRAINT `dasapp_doctorreg_admin_id_a8e63d8d_fk_dasapp_customuser_id` FOREIGN KEY (`admin_id`) REFERENCES `dasapp_customuser` (`id`),
  ADD CONSTRAINT `dasapp_doctorreg_specialization_id_id_053c14bd_fk_dasapp_sp` FOREIGN KEY (`specialization_id_id`) REFERENCES `dasapp_specialization` (`id`);

--
-- Các ràng buộc cho bảng `django_admin_log`
--
ALTER TABLE `django_admin_log`
  ADD CONSTRAINT `django_admin_log_content_type_id_c4bce8eb_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`),
  ADD CONSTRAINT `django_admin_log_user_id_c564eba6_fk_dasapp_customuser_id` FOREIGN KEY (`user_id`) REFERENCES `dasapp_customuser` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
