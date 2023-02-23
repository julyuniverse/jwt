drop table member;
create table member
(
    member_id bigint auto_increment primary key,
    email     varchar(100) not null,
    password  varchar(255) not null,
    authority varchar(50) not null
);