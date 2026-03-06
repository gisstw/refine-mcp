<?php
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void {
        Schema::create('pricing_deposit', function (Blueprint $table) {
            $table->increments('id');
            $table->string('price');
            $table->enum('type', ['1', '2', '3']);
            $table->unsignedInteger('reservation_id');
            $table->boolean('fail')->default(false);
            $table->foreign('reservation_id')->references('id')->on('reservations')->onDelete('cascade');
            $table->timestamps();
        });
    }
};
