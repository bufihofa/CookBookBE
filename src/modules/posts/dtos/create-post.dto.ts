// src/modules/recipes/dtos/create-recipe.dto.ts
import { IsString, IsNotEmpty, IsOptional, IsNumber, IsArray, ValidateNested, IsUrl, ArrayMinSize } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import exp from 'constants';
import { Post } from '../entities/post.entity';
import { User } from 'src/modules/auth/entities/user.entity';

class IngredientDto {
  @IsString()
  @IsNotEmpty()
  @ApiProperty({ description: 'Tên nguyên liệu', example: 'Thịt heo' })
  name: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({ description: 'Số lượng nguyên liệu', example: '500g' })
  quantity: string;
}
export class ReponseUserDto{
  constructor(user?: User) {
    if (user) {
        const { id, username, name, avatar } = user;
        Object.assign(this, { id, username, name, avatar });
    }
  }
  @IsNumber()
  @IsNotEmpty()
  id: number;

  @IsString()
  @IsNotEmpty()
  username: string;

  @IsString()
  @IsOptional()
  name?: string;

  @IsUrl()
  @IsOptional()
  avatar?: string;
}
export class LiteReponsePostDto{
  constructor(post?: Post) {
    if (post) {
        const { author, title, description, cookTime, mainImage, totalView, totalComment, totalLike } = post;
        const authorDto = new ReponseUserDto(author);
        Object.assign(this, { author: authorDto, title, description, cookTime, mainImage, totalView, totalComment, totalLike });
    }
  }
  @Type(() => ReponseUserDto)
  author: ReponseUserDto;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({ description: 'Tiêu đề bài viết', example: 'Sườn xào chua ngọt' })
  title: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({ description: 'Mô tả bài viết', example: 'Món sườn xào chua ngọt thơm ngon, dễ làm' })
  description: string;

  @IsOptional()
  @IsString()
  @ApiPropertyOptional({ description: 'Thời gian nấu', example: '45 phút' })
  cookTime?: string;

  @IsOptional()
  @IsUrl()
  @ApiPropertyOptional({ description: 'Hình ảnh chính của món ăn', example: 'https://file.hstatic.net/200000610729/file/suon-3_022e54b9753f433ea8d5e2b7466b3484.jpg' })
  mainImage?: string;

  totalView?: number;
  totalFavorite?: number;
  totalComment?: number;
  totalLike?: number;
}
export class FullReponsePostDto{
  constructor(post?: Post) {
    if (post) {
        Object.assign(this, post);
    }
}
  @Type(() => ReponseUserDto)
  author: ReponseUserDto;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({ description: 'Tiêu đề bài viết', example: 'Sườn xào chua ngọt' })
  title: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({ description: 'Mô tả bài viết', example: 'Món sườn xào chua ngọt thơm ngon, dễ làm' })
  description: string;

  @IsOptional()
  @IsString()
  @ApiPropertyOptional({ description: 'Thời gian nấu', example: '45 phút' })
  cookTime?: string;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => IngredientDto)
  @ApiPropertyOptional({ description: 'Danh sách nguyên liệu', example: [{ name: 'Sườn heo non', quantity: '500g' }, { name: 'Hành', quantity: '1 củ' }, { name: 'Cà chua', quantity: '2 quả' }] })
  ingredient?: IngredientDto[];

  @IsOptional()
  @IsArray()
  @ApiPropertyOptional({ description: 'Cách nấu', example: ['Sườn non rửa sạch, chặt miếng vừa ăn.','Ướp sườn với gia vị trong 30 phút','Pha nước sốt chua ngọt','Phi thơm hành, xào sườn rồi cho nguyên liệu vào'] })
  steps?: string[];

  @IsOptional()
  @IsUrl()
  @ApiPropertyOptional({ description: 'Hình ảnh chính của món ăn', example: 'https://file.hstatic.net/200000610729/file/suon-3_022e54b9753f433ea8d5e2b7466b3484.jpg' })
  mainImage?: string;

  totalView?: number;
  totalFavorite?: number;
  totalComment?: number;
  totalLike?: number;
}
export class CreatePostDto {
  @IsString()
  @IsNotEmpty()
  @ApiProperty({ description: 'Tiêu đề bài viết', example: 'Sườn xào chua ngọt' })
  title: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({ description: 'Mô tả bài viết', example: 'Món sườn xào chua ngọt thơm ngon, dễ làm' })
  description: string;

  @IsOptional()
  @IsString()
  @ApiPropertyOptional({ description: 'Thời gian nấu', example: '45 phút' })
  cookTime?: string;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => IngredientDto)
  @ApiPropertyOptional({ description: 'Danh sách nguyên liệu', example: [{ name: 'Sườn heo non', quantity: '500g' }, { name: 'Hành', quantity: '1 củ' }, { name: 'Cà chua', quantity: '2 quả' }] })
  ingredient?: IngredientDto[];

  @IsOptional()
  @IsArray()
  @ApiPropertyOptional({ description: 'Cách nấu', example: ['Sườn non rửa sạch, chặt miếng vừa ăn.','Ướp sườn với gia vị trong 30 phút','Pha nước sốt chua ngọt','Phi thơm hành, xào sườn rồi cho nguyên liệu vào'] })
  steps?: string[];

  @IsOptional()
  @IsUrl()
  @ApiPropertyOptional({ description: 'Hình ảnh chính của món ăn', example: 'https://file.hstatic.net/200000610729/file/suon-3_022e54b9753f433ea8d5e2b7466b3484.jpg' })
  mainImage?: string;
}